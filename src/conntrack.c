/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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

#define MAX_CONNTRACK MAX_MATCH

#define CONNTRACK_SIZE 1048576

#define INITVAL 0xdf92b6eb

struct conntrack_reg *conntracks[MAX_CONNTRACK];
struct conntrack_list *ct_table[CONNTRACK_SIZE];
struct conntrack_list *ct_table_rev[CONNTRACK_SIZE];
struct conntrack_functions *ct_funcs;


int conntrack_init() {

	int i;
	
	for (i = 0; i < CONNTRACK_SIZE; i ++) {
		ct_table[i] = NULL;
		ct_table_rev[i] = NULL;
	}

	ct_funcs = malloc(sizeof(struct conntrack_functions));
	ct_funcs->alloc_timer = conntrack_timer_alloc;
	ct_funcs->cleanup_timer = timer_cleanup;
	ct_funcs->queue_timer = timer_queue;
	ct_funcs->dequeue_timer = timer_dequeue;

	dprint("Conntrack initialized\n");
	
	return 1;

}

int conntrack_register(const char *conntrack_name) {


	int id;
	id = match_get_type(conntrack_name);
	if (id == -1) {
		dprint("Unable to register conntrack %s. Corresponding match not found\n", conntrack_name);
		return -1;
	}

	if (conntracks[id])
		return id;

	int (*register_my_conntrack) (struct conntrack_reg *, struct conntrack_functions *);

	void *handle = NULL;
	register_my_conntrack = lib_get_register_func("conntrack", conntrack_name, &handle);
	
	if (!register_my_conntrack) {
		return -1;
	}

	struct conntrack_reg *my_conntrack = malloc(sizeof(struct conntrack_reg));
	bzero(my_conntrack, sizeof(struct conntrack_reg));


	if (!(*register_my_conntrack) (my_conntrack, ct_funcs)) {
		dprint("Error while loading conntrack %s. Could not register conntrack !\n", conntrack_name);
		free(my_conntrack);
		return -1;
	}

	conntracks[id] = my_conntrack;
	conntracks[id]->dl_handle = handle;

	dprint("Conntrack %s registered\n", conntrack_name);


	return id;


}

int conntrack_create_entry(struct frame *f) {
	
	struct conntrack_list *cl, *cl_rev;

	cl = malloc(sizeof(struct conntrack_list));
	bzero(cl, sizeof(struct conntrack_list));

	cl_rev = malloc(sizeof(struct conntrack_list));
	bzero(cl_rev, sizeof(struct conntrack_list));

	// Make those two conntrack_list linked
	cl->rev = cl_rev;
	cl_rev->rev = cl;


	uint32_t hash = conntrack_hash(f, CT_DIR_ONEWAY);	
	uint32_t hash_rev = conntrack_hash(f, CT_DIR_REV);
	
	struct conntrack_entry *ce;

	ce = malloc(sizeof(struct conntrack_entry));
	bzero(ce, sizeof(struct conntrack_entry));

	ce->full_hash = hash;

	cl->ce = ce;
	cl->hash = hash;
	cl->next = ct_table[hash];
	ct_table[hash] = cl;

	cl_rev->ce = ce;
	cl_rev->hash = hash_rev;
	cl_rev->next = ct_table_rev[hash_rev];
	ct_table_rev[hash_rev] = cl_rev;


	// TODO : add matches in the opposite direction for speed
	
	struct layer *l = f->l;

	while (l) {
		if (conntracks[l->type] && conntracks[l->type]->alloc_match_priv) {
			int start = 0;
			if (l->prev)
				start = l->prev->payload_start;
			void *priv = (*conntracks[l->type]->alloc_match_priv) (f, start, ce);
			struct conntrack_match_priv *cp;
			cp = malloc(sizeof(struct conntrack_match_priv));
			cp->priv_type = l->type;
			cp->priv = priv;
			cp->next = ce->match_privs;
			ce->match_privs = cp;
		}
		l = l->next;
	}

	ndprint("Conntrack entry 0x%lx created\n", (unsigned long) ce);

	ce->direction = CT_DIR_FWD;
	f->ce = ce;

	return C_OK;
}


/**
* The obj is a variable which is used to identify target. The value of the struct target should be given.
**/
int conntrack_add_target_priv(void *priv, struct target *t, struct conntrack_entry *ce, int (*cleanup_handler) (struct conntrack_entry *ce, void *priv)) {

	// Let's see if that priv_type is already present

	struct conntrack_target_priv *cp;

#ifdef DEBUG
	cp = ce->target_privs;
	while (cp) {
		if (cp->t == t) {
			dprint("Warning. Target priv already added\n");
			return 0;
		}
		cp = cp->next;
	}
#endif

	// Ok it's not. Creating a new conntrack_priv for our target

	cp = malloc(sizeof(struct conntrack_target_priv));
	bzero(cp, sizeof(struct conntrack_target_priv));

	cp->next = ce->target_privs;
	ce->target_privs = cp;

	cp->t = t;
	cp->priv = priv;
	cp->cleanup_handler = cleanup_handler;

	ndprint("Target priv 0x%lx added to conntrack 0x%lx\n", (unsigned long) priv, (unsigned long) ce);

	
	return 1;
}


int conntrack_add_helper_priv(void *priv, int type, struct conntrack_entry *ce, int (*flush_buffer) (struct conntrack_entry *ce, void *priv), int (*cleanup_handler) (struct conntrack_entry *ce, void *priv)) {

	// Let's see if that priv_type is already present

	struct conntrack_helper_priv *cp;

#ifdef DEBUG
	cp = ce->helper_privs;
	while (cp) {
		if (cp->type == type) {
			dprint("Warning. Helper priv already added\n");
			return 0;
		}
		cp = cp->next;
	}
#endif

	// Ok it's not. Creating a new conntrack_priv for our target

	cp = malloc(sizeof(struct conntrack_helper_priv));
	bzero(cp, sizeof(struct conntrack_helper_priv));

	cp->next = ce->helper_privs;
	ce->helper_privs = cp;

	cp->type = type;
	cp->priv = priv;
	cp->flush_buffer = flush_buffer;
	cp->cleanup_handler = cleanup_handler;

	ndprint("Helper priv 0x%lx added to conntrack 0x%lx\n", (unsigned long) priv, (unsigned long) ce);

	
	return 1;
}

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
			if (!flags || (flags & conntracks[l->type]->flags)) {
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

int conntrack_get_entry(struct frame *f) {
	
	uint32_t hash;

	// Let's start by calculating the full hash

	hash = conntrack_hash(f, CT_DIR_ONEWAY);

	struct conntrack_list *cl;
	cl = ct_table[hash];

	struct conntrack_entry *ce;
	ce = conntrack_find(cl, f, CT_DIR_ONEWAY);


	if (ce) {

		ce->direction = CT_DIR_FWD;

	} else {// Conntrack not found. Let's try the opposite direction
		// We need the match the forward hash in the reverse table
		uint32_t hash_fwd = conntrack_hash(f, CT_DIR_FWD);	
		cl = ct_table_rev[hash_fwd];
		ce = conntrack_find(cl, f, CT_DIR_REV);
		if (ce)
			ce->direction = CT_DIR_REV;
	}


	if (ce) { 
		f->ce = ce;
		return C_OK;
	}

	f->ce = NULL;
	return C_ERR;

}

struct conntrack_entry *conntrack_find(struct conntrack_list *cl, struct frame *f, unsigned int flags) {

	if (!cl)
		return NULL;

	struct conntrack_entry *ce;
	ce = cl->ce;

	struct conntrack_match_priv *cp;
	cp = ce->match_privs;

	struct layer *l = f->l;

	while (cp) {

		int start = layer_find_start(l, cp->priv_type);

		if (!flags || (flags & conntracks[cp->priv_type]->flags)) { 

			if (start == -1 || !(*conntracks[cp->priv_type]->doublecheck) (f, start, cp->priv, flags)) {

				cl = cl->next; // If it's not the right conntrack entry, go to next one
				if (!cl)
					return NULL; // No entry matched
				ce = cl->ce;
				cp = ce->match_privs;
				continue;
			}
		}

		cp = cp->next;
	}

	ndprint("Found conntrack 0x%lx, hash 0x%lx\n", (unsigned long) ce, ce->full_hash);

	return ce;
}

int conntrack_cleanup_connection(struct conntrack_entry *ce) {

	// Remove the match privs
	struct conntrack_match_priv *mp, *mptmp;
	mp = ce->match_privs;
	while (mp) {
		if (conntracks[mp->priv_type] && conntracks[mp->priv_type]->cleanup_match_priv)
			(*conntracks[mp->priv_type]->cleanup_match_priv) (mp->priv);

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
			(*tp->cleanup_handler) (ce, tp->priv);
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
		dprint("Warning, conntrack_list not found for conntrack 0x%lu\n", (unsigned long) ce);

	// Free the conntrack_entry itself

	free (ce);


	return 1;
}


int conntrack_close_connection(struct conntrack_entry *ce) {

	struct conntrack_helper_priv *hp;

	// Let's start by emptying out the buffer. We may not need to close it after all
	hp = ce->helper_privs;
	while (hp) {
		if (hp->priv && hp->flush_buffer)
			if ((*hp->flush_buffer) (ce, hp->priv))
				return 0; // There was stuff in the buffer. Let's not close it
		hp = hp->next;
	}

	// Now we can clean and close stuff out
	
	return 1;
}

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
				while ((*hp->flush_buffer) (cl->ce, hp->priv))
					helper_process_queue(r);

				hp = hp->next;
			}

			cl = cl->next;
		}
	}

	return 1;

}

int conntrack_cleanup() {

	int i;

	// Cleanup remaining connections

	for (i = 0; i < CONNTRACK_SIZE; i ++) {
		while (ct_table[i]) {
			conntrack_cleanup_connection(ct_table[i]->ce);
		}
	}

	free(ct_funcs);

	return 1;

}

int conntrack_unregister_all() {

	int i;

	for (i = 0; i < MAX_CONNTRACK; i++) {
		if (conntracks[i]) {
			dlclose(conntracks[i]->dl_handle);
			free(conntracks[i]);
			conntracks[i] = NULL;
		}

	}

	return 1;

}

int conntrack_do_timer(void * ce) {

	conntrack_close_connection(ce);
	conntrack_cleanup_connection(ce);
	return 1;
}

struct timer *conntrack_timer_alloc(struct conntrack_entry *ce, struct input *i) {

	return timer_alloc(ce, i, conntrack_do_timer);
}

