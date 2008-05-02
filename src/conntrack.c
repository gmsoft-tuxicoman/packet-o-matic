/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "common.h"
#include "conntrack.h"
#include "target.h"
#include "timers.h"
#include "ptype.h"

#define CONNTRACK_SIZE 1048576

#define INITVAL 0xdf92b6eb

struct conntrack_list *ct_table[CONNTRACK_SIZE];
struct conntrack_list *ct_table_rev[CONNTRACK_SIZE];

/**
 * @ingroup conntrack_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_init() {

	int i;
	
	for (i = 0; i < CONNTRACK_SIZE; i ++) {
		ct_table[i] = NULL;
		ct_table_rev[i] = NULL;
	}

	pom_log(POM_LOG_DEBUG "Conntrack initialized\r\n");
	
	return POM_OK;

}

/**
 * @ingroup conntrack_core
 * @param conntrack_name Name of the conntrack
 * @return Type of the conntrack on success or POM_ERR on error.
 */
int conntrack_register(const char *conntrack_name) {


	int id;
	id = match_get_type(conntrack_name);
	if (id == POM_ERR) {
		pom_log(POM_LOG_WARN "Unable to register conntrack %s. Corresponding match not found\r\n", conntrack_name);
		return POM_ERR;
	}

	if (conntracks[id])
		return id;

	int (*register_my_conntrack) (struct conntrack_reg *);

	void *handle = NULL;
	register_my_conntrack = lib_get_register_func("conntrack", conntrack_name, &handle);
	
	if (!register_my_conntrack) {
		return POM_ERR;
	}

	struct conntrack_reg *my_conntrack = malloc(sizeof(struct conntrack_reg));
	memset(my_conntrack, 0, sizeof(struct conntrack_reg));
	my_conntrack->type = id;
	conntracks[id] = my_conntrack;
	conntracks[id]->dl_handle = handle;

	if ((*register_my_conntrack) (my_conntrack) != POM_OK) {
		pom_log(POM_LOG_ERR "Error while loading conntrack %s. Could not register conntrack !\r\n", conntrack_name);
		conntracks[id] = NULL;
		free(my_conntrack);
		return POM_ERR;
	}


	pom_log(POM_LOG_DEBUG "Conntrack %s registered\r\n", conntrack_name);


	return id;


}

/**
 * @ingroup conntrack_api
 * @param conntrack_type Type of the conntrack
 * @param name Name of the parameter to regiter
 * @param defval Default value
 * @param value Pointer to the actual value
 * @param descr Description
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_register_param(int conntrack_type, char *name, char *defval, struct ptype *value, char *descr) {

	if (!conntracks[conntrack_type])
		return POM_ERR;

	if (ptype_parse_val(value, defval) == POM_ERR)
		return POM_ERR;

	struct conntrack_param *p = malloc(sizeof(struct conntrack_param));
	memset(p, 0, sizeof(struct conntrack_param));
	p->name = malloc(strlen(name) + 1);
	strcpy(p->name, name);
	p->defval = malloc(strlen(defval) + 1);
	strcpy(p->defval, defval);
	p->descr = malloc(strlen(descr) + 1);
	strcpy(p->descr, descr);
	p->value = value;

	if (!conntracks[conntrack_type]->params) {
		conntracks[conntrack_type]->params = p;
	} else {
		struct conntrack_param *tmp = conntracks[conntrack_type]->params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = p;
	}

	return POM_OK;

}

/**
 * @ingroup conntrack_core
 * @param conntrack_type Type of the conntrack to get the parameter from
 * @param param_name Name of the parameter
 * @return Pointer to the parameter or NULL on error.
 */
struct conntrack_param *conntrack_get_param(int conntrack_type, char *param_name) {

	if (!conntracks[conntrack_type])
		return NULL;

	struct conntrack_param *p = conntracks[conntrack_type]->params;

	while (p) {
		if (!strcmp(p->name, param_name))
			return p;
		p = p->next;
	}

	return NULL;

}

/**
 * @ingroup conntrack_api
 * The function will set f->ce with the newly created entry
 * @param f Frame to create a conntrack entry from
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_create_entry(struct frame *f) {

	if (f->ce) {
		pom_log(POM_LOG_WARN "Conntrack entry already exists for this frame\r\n");
		return POM_OK;
	}

	uint32_t hash = conntrack_hash(f, CT_DIR_ONEWAY);	
	uint32_t hash_rev = conntrack_hash(f, CT_DIR_REV);
	
	struct conntrack_entry *ce;

	ce = malloc(sizeof(struct conntrack_entry));
	memset(ce, 0, sizeof(struct conntrack_entry));

	ce->full_hash = hash;


	struct layer *l = f->l;
	struct conntrack_match_priv *lastcp = NULL;

	while (l) {
		if (conntracks[l->type] && conntracks[l->type]->alloc_match_priv) {
			int start = 0;
			if (l->prev)
				start = l->prev->payload_start;
			void *priv = (*conntracks[l->type]->alloc_match_priv) (f, start, ce);
			struct conntrack_match_priv *cp;
			cp = malloc(sizeof(struct conntrack_match_priv));
			memset(cp, 0, sizeof(struct conntrack_match_priv));
			cp->priv_type = l->type;
			cp->priv = priv;
			
			if (lastcp) 
				lastcp->next = cp;
			else 
				ce->match_privs = cp;

			lastcp = cp;

			conntracks[l->type]->refcount++;
		}
		l = l->next;
	}

	if (!ce->match_privs) {
		// no match priv was created, we can't track this connection
		free(ce);
		return POM_ERR;
	}

	struct conntrack_list *cl, *cl_rev;

	cl = malloc(sizeof(struct conntrack_list));
	memset(cl, 0, sizeof(struct conntrack_list));

	cl_rev = malloc(sizeof(struct conntrack_list));
	memset(cl_rev, 0, sizeof(struct conntrack_list));

	// Make those two conntrack_list linked
	cl->rev = cl_rev;
	cl_rev->rev = cl;


	cl->ce = ce;
	cl->hash = hash;
	cl->next = ct_table[hash];
	ct_table[hash] = cl;

	cl_rev->ce = ce;
	cl_rev->hash = hash_rev;
	cl_rev->next = ct_table_rev[hash_rev];
	ct_table_rev[hash_rev] = cl_rev;

	pom_log(POM_LOG_TSHOOT "Conntrack entry 0x%lx created\r\n", (unsigned long) ce);

	ce->direction = CE_DIR_FWD;
	f->ce = ce;

	return POM_OK;
}


/**
* @ingroup conntrack_api
* @param priv Private data to remember
* @param t Target who the private data belongs to
* @param ce Conntrack entry associated with this private data
* @param cleanup_handler Cleanup handler for the private data when the connection is closed
* @return POM_OK on success, POM_ERR on failure.
*/
int conntrack_add_target_priv(void *priv, struct target *t, struct conntrack_entry *ce, int (*cleanup_handler) (struct target *t, struct conntrack_entry *ce, void *priv)) {

	// Let's see if that priv_type is already present

	struct conntrack_target_priv *cp;

#ifdef DEBUG
	cp = ce->target_privs;
	while (cp) {
		if (cp->t == t) {
			pom_log(POM_LOG_WARN "Warning. Target priv already added\r\n");
			return POM_ERR;
		}
		cp = cp->next;
	}
#endif

	// Ok it's not. Creating a new conntrack_priv for our target

	cp = malloc(sizeof(struct conntrack_target_priv));
	memset(cp, 0, sizeof(struct conntrack_target_priv));

	cp->next = ce->target_privs;
	ce->target_privs = cp;

	cp->t = t;
	cp->priv = priv;
	cp->cleanup_handler = cleanup_handler;
	
	pom_log(POM_LOG_TSHOOT "Target priv 0x%lx added to conntrack 0x%lx\r\n", (unsigned long) priv, (unsigned long) ce);

	
	return POM_OK;
}

/**
 * @ingroup conntrack_api
 * This function must be called when the connection is closed by the target.
 * This allows the conntrack subsystem to clean the connection entry if needed.
 * @param priv Private data to remove
 * @param ce Conntrack entry associated with the private data
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_remove_target_priv(void* priv, struct conntrack_entry *ce) {

	if (!ce)
		return POM_ERR;
	
	struct conntrack_target_priv *cp = ce->target_privs;

	// Remove the first element if it match
	if (cp->priv == priv) {
		ce->target_privs = cp->next;
		free(cp);
	} else {
		struct conntrack_target_priv *prev;
		while (cp) {
			prev = cp;
			cp = cp->next;
			if (cp->priv == priv) {
				prev->next = cp->next;
				free(cp);
			}
			break;
		}
	}

	if (!ce->helper_privs && !ce->target_privs) {
		// No relevant info attached to this conntrack. We can safely clean it up
		conntrack_cleanup_connection(ce);
	}

	return POM_OK;
}

/**
* @ingroup conntrack_api
* @param priv Private data to remember
* @param type Type of the helper who the private data belongs to
* @param ce Conntrack entry associated with this private data
* @param flush_buffer The connection is about to be closed and we flush the buffers to make sure there is no packet remaining
* @param cleanup_handler Cleanup handler for the private data when the connection is closed
* @return POM_OK on success, POM_ERR on failure.
*/
int conntrack_add_helper_priv(void *priv, int type, struct conntrack_entry *ce, int (*flush_buffer) (struct conntrack_entry *ce, void *priv), int (*cleanup_handler) (struct conntrack_entry *ce, void *priv)) {

	// Let's see if that priv_type is already present

	struct conntrack_helper_priv *cp;

#ifdef DEBUG
	cp = ce->helper_privs;
	while (cp) {
		if (cp->type == type) {
			pom_log(POM_LOG_WARN "Warning. Helper priv already added\r\n");
			return POM_ERR;
		}
		cp = cp->next;
	}
#endif

	// Ok it's not. Creating a new conntrack_priv for our target

	cp = malloc(sizeof(struct conntrack_helper_priv));
	memset(cp, 0, sizeof(struct conntrack_helper_priv));

	cp->next = ce->helper_privs;
	ce->helper_privs = cp;

	cp->type = type;
	cp->priv = priv;
	cp->flush_buffer = flush_buffer;
	cp->cleanup_handler = cleanup_handler;

	pom_log(POM_LOG_TSHOOT "Helper priv 0x%lx added to conntrack 0x%lx\r\n", (unsigned long) priv, (unsigned long) ce);

	
	return POM_OK;
}

/**
 * @ingroup conntrack_api
 * @param type Type of the helper to get the private data from
 * @param ce Conntrack entry to which the private data is associated
 * @return Pointer to the private data or NULL on error.
 */
void *conntrack_get_helper_priv(int type, struct conntrack_entry *ce) {


	if (!ce)
		return NULL;

	struct conntrack_helper_priv *cp;
	cp = ce->helper_privs;
	while (cp) {
		if (cp->type == type) {
			return cp->priv;
		}
		cp = cp->next;
	}

	return NULL;
}

/**
 * @ingroup conntrack_api
 * This function must be called when the connection is closed by the helper.
 * This allows the conntrack subsystem to clean the connection entry if needed.
 * @param priv Private data to remove
 * @param ce Conntrack entry associated with the private data
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_remove_helper_priv(void* priv, struct conntrack_entry *ce) {

	if (!ce)
		return POM_ERR;
	
	struct conntrack_helper_priv *cp = ce->helper_privs;
	
	// Remove the first element if it match
	if (cp->priv == priv) {
		ce->helper_privs = cp->next;
		free(cp);
	} else {
		struct conntrack_helper_priv *prev;
		while (cp) {
			prev = cp;
			cp = cp->next;
			if (cp->priv == priv) {
				prev->next = cp->next;
				free(cp);
			}
			break;
		}
	}

	if (!ce->helper_privs && !ce->target_privs) {
		// No relevant info attached to this conntrack. We can safely clean it up
		conntrack_cleanup_connection(ce);
	}

	return POM_OK;
}

/**
 * @ingroup conntrack_api
 * @param t Target to get the private data from
 * @param ce Conntrack entry to which the private data is associated
 * @return Pointer to the private data or NULL on error.
 */
void *conntrack_get_target_priv(struct target *t, struct conntrack_entry *ce) {


	if (!ce)
		return NULL;

	struct conntrack_target_priv *cp;
	cp = ce->target_privs;
	while (cp) {
		if (cp->t == t) {
			return cp->priv;
		}
		cp = cp->next;
	}

	return NULL;
}

/**
 * @ingroup conntrack_api
 * @param f Frame to get a hash for
 * @param flags What type of heash to create
 * @return The computed hash.
 */
uint32_t conntrack_hash(struct frame *f, unsigned int flags) {


	// Compute our hash for each layer
	uint32_t hash, res;
	hash = INITVAL;

	struct layer *l = f->l;

	while (l && l->type != -1) {

		if (conntracks[l->type]) {
			// We compute the hash in two case only :
			//  - if flags = CT_DIR_ONEWAY
			//  - if the direction provided in flags (fwd or rev) is present in the conntrack module flags
			if (flags == CT_DIR_ONEWAY || (flags & conntracks[l->type]->flags)) {
				int start = layer_find_start(l, l->type);
				res = (*conntracks[l->type]->get_hash) (f, start, flags);
				hash = jhash_2words(hash, res, INITVAL);
			}

		}
		l = l->next;
	}

	hash %= CONNTRACK_SIZE;

	return hash;
}

/**
 * @ingroup conntrack_api
 * @param f Frame to test
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_get_entry(struct frame *f) {
	
	uint32_t hash;

	// Let's start by calculating the full hash

	hash = conntrack_hash(f, CT_DIR_ONEWAY);

	struct conntrack_list *cl;
	cl = ct_table[hash];

	struct conntrack_entry *ce;
	ce = conntrack_find(cl, f, CT_DIR_ONEWAY);


	if (ce) {

		ce->direction = CE_DIR_FWD;

	} else {// Conntrack not found. Let's try the opposite direction
		// We need the match the forward hash in the reverse table
		uint32_t hash_fwd = conntrack_hash(f, CT_DIR_FWD);	
		cl = ct_table_rev[hash_fwd];
		ce = conntrack_find(cl, f, CT_DIR_REV);
		if (ce)
			ce->direction = CE_DIR_REV;
	}


	if (ce) { 
		f->ce = ce;
		return POM_OK;
	}

	f->ce = NULL;
	return POM_ERR;

}

/**
 * @ingroup conntrack_core
 * @param cl Conntrack list to search
 * @param f Frame to test
 * @param flags How to match the conntracks
 * @return The conntrack entry found or NULL on failure.
 */
struct conntrack_entry *conntrack_find(struct conntrack_list *cl, struct frame *f, unsigned int flags) {

	if (!cl)
		return NULL;

	struct conntrack_entry *ce;
	ce = cl->ce;

	struct conntrack_match_priv *cp;
	cp = ce->match_privs;

	struct layer *l = f->l;
	int start = 0;

	while (l) {
		
		if (l->type == cp->priv_type) {
	
			if ((*conntracks[cp->priv_type]->doublecheck) (f, start, cp->priv, flags) == POM_ERR) {
				cl = cl->next;
				if (!cl)
					return NULL;
				l = f->l;
				start = 0;
				ce = cl->ce;
				cp = ce->match_privs;
				continue;

			}
			cp = cp->next;

			if (!cp)
				return ce;
		}

		start = l->payload_start;
		l = l->next;
	}

	//pom_log(POM_LOG_TSHOOT "Found conntrack 0x%lx, hash 0x%lx\r\n", (unsigned long) ce, ce->full_hash);

	return ce;
}

/**
 * @ingroup conntrack_api
 * @param ce Conntrack entry to cleanup
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_cleanup_connection(struct conntrack_entry *ce) {

	// Remove the match privs
	struct conntrack_match_priv *mp, *mptmp;
	mp = ce->match_privs;
	while (mp) {
		if (conntracks[mp->priv_type] && conntracks[mp->priv_type]->cleanup_match_priv)
			(*conntracks[mp->priv_type]->cleanup_match_priv) (mp->priv);
		conntracks[mp->priv_type]->refcount--;
		mptmp = mp;
		mp = mp->next;
		free(mptmp);
	}

	// Free up the helper privs
	
	struct conntrack_helper_priv *hp, *hptmp;
	hp = ce->helper_privs;
	while (hp) {
		if (hp->priv && hp->cleanup_handler)
			(*hp->cleanup_handler) (ce, hp->priv);
		hptmp = hp;
		hp = hp->next;
		free(hptmp);
	}

	// Free up the target privs

	struct conntrack_target_priv *tp, *tptmp;
	tp = ce->target_privs;
	while (tp) {
		if (tp->priv && tp->cleanup_handler)
			(*tp->cleanup_handler) (tp->t, ce, tp->priv);
		tptmp = tp;
		tp = tp->next;
		free(tptmp);
	}


	// Free the conntrack lists

	struct conntrack_list *cl;
	
	cl = ct_table[ce->full_hash];

	// Find out the right conntrack_list
	while (cl) {
		if (cl->ce == ce)
			break;
		cl = cl->next;
	}

	// Dequeue the list if found
	if (cl) {

		struct conntrack_list *cltmp;
	
		// Remove in the forward table
		if (ct_table[cl->hash] == cl)
			ct_table[cl->hash] = cl->next;
		else  {
			cltmp = ct_table[cl->hash];
			while (cltmp->next) {
				if (cltmp->next == cl) {
					cltmp->next = cl->next;
					break;
				}
				cltmp = cltmp->next;
			}
		}


		// Remove in the reverse table
		cltmp = cl;
		cl = cl->rev;
		free(cltmp);	
		
		if (ct_table_rev[cl->hash] == cl)
			ct_table_rev[cl->hash] = cl->next;
		else  {
			cltmp = ct_table_rev[cl->hash];
			while (cltmp->next) {
				if (cltmp->next == cl) {
					cltmp->next = cl->next;
					break;
				}
				cltmp = cltmp->next;
			}

		}

		free(cl);
	
	} else
		pom_log(POM_LOG_WARN "Warning, conntrack_list not found for conntrack 0x%lu\r\n", (unsigned long) ce);

	// Free the conntrack_entry itself

	free (ce);


	return POM_OK;
}

/**
 * @ingroup conntrack_core
 * @param ce Conntrack_entry to close
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_close_connection(struct conntrack_entry *ce) {

	struct conntrack_helper_priv *hp;

	// Let's start by emptying out the buffer. We may not need to close it after all
	hp = ce->helper_privs;
	while (hp) {
		if (hp->priv && hp->flush_buffer)
			if ((*hp->flush_buffer) (ce, hp->priv) == POM_OK)
				return POM_ERR; // There was stuff in the buffer. Let's not close it
		hp = hp->next;
	}

	// Now we can clean and close stuff out
	
	return POM_OK;
}

/**
 * @ingroup conntrack_core
 * @param r Rule list to use for packets that are still in the buffer
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_close_connections(struct rule_list *r) {

	int i;

	// Close remaining connections

	for (i = 0; i < CONNTRACK_SIZE; i ++) {
		struct conntrack_list *cl = ct_table[i];
		while (cl) {
			conntrack_close_connection(cl->ce);
			// At this point we want to process all the remaining packets in the buffer
			
			struct conntrack_helper_priv *hp = cl->ce->helper_privs;
			while (hp) {
				while ((*hp->flush_buffer) (cl->ce, hp->priv) == POM_OK)
					helper_process_queue(r);

				hp = hp->next;
			}

			cl = cl->next;
		}
	}

	return POM_OK;

}

/**
 * @ingroup conntrack_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_cleanup() {

	int i;

	// Cleanup remaining connections

	for (i = 0; i < CONNTRACK_SIZE; i ++) {
		while (ct_table[i]) {
			conntrack_cleanup_connection(ct_table[i]->ce);
		}
	}


	return POM_OK;

}

/**
 * @ingroup conntrack_core
 * @param conntrack_type Type of the conntrack to unregiter
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_unregister(int conntrack_type) {

	if (conntracks[conntrack_type]) {
		if (conntracks[conntrack_type]->refcount) {	
			pom_log(POM_LOG_WARN "Warning, reference count not 0 for conntrack %s\r\n", match_get_name(conntrack_type));
			return POM_ERR;
		}
		if (conntracks[conntrack_type]->unregister)
			(*conntracks[conntrack_type]->unregister) (conntracks[conntrack_type]);
		while (conntracks[conntrack_type]->params) {
			free(conntracks[conntrack_type]->params->name);
			free(conntracks[conntrack_type]->params->defval);
			free(conntracks[conntrack_type]->params->descr);
			struct conntrack_param *next = conntracks[conntrack_type]->params->next;
			free(conntracks[conntrack_type]->params);
			conntracks[conntrack_type]->params = next;
		}
		if (dlclose(conntracks[conntrack_type]->dl_handle))
			pom_log(POM_LOG_WARN "Error while closing library of conntrack %s\r\n", match_get_name(conntrack_type));
		free(conntracks[conntrack_type]);
		conntracks[conntrack_type] = NULL;
		pom_log(POM_LOG_DEBUG "Conntrack %s unregistered\r\n", match_get_name(conntrack_type));
	}

	return POM_OK;

}

/**
 * @ingroup conntrack_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_unregister_all() {

	int i;
	int result = POM_OK;

	for (i = 0; i < MAX_CONNTRACK; i++) {
		if (conntracks[i])
			if (conntrack_unregister(i) == POM_ERR)
				result = POM_ERR;
	}

	return result;

}

/**
 * @ingroup conntrack_core
 * @param ce Conntrack entry for which the timer expired
 * @return POM_OK on success, POM_ERR on failure.
 */
int conntrack_do_timer(void * ce) {

	if (conntrack_close_connection(ce) == POM_ERR)
		return POM_OK;
	conntrack_cleanup_connection(ce);
	return POM_OK;
}

/**
 * @ingroup conntrack_api
 * @param ce Conntrack entry
 * @param i Input used for the packet
 * @return POM_OK on success, POM_ERR on error.
 */
struct timer *conntrack_timer_alloc(struct conntrack_entry *ce, struct input *i) {

	return timer_alloc(ce, i, conntrack_do_timer);
}

