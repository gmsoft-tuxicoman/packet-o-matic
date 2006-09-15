

#include "conntrack.h"

#define MAX_CONNTRACK 16

#define CONNTRACK_SIZE 65535

#define INITVAL 0xdf92b6eb


struct conntrack_reg *conntracks[MAX_CONNTRACK];
struct conntrack_entry *ct_table[CONNTRACK_SIZE];

int conntrack_init() {

	int i;
	
	for (i = 0; i < CONNTRACK_SIZE; i ++)
		ct_table[i] = NULL;

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


	void *handle;
	char name[255];
	strcpy(name, "./conntrack_");
	strcat(name, conntrack_name);
	strcat(name, ".so");

	handle = dlopen(name, RTLD_NOW);

	if (!handle) {
		dprint("Unable to load conntrack %s : ", conntrack_name);
		dprint(dlerror());
		dprint("\n");
		return -1;
	}
	dlerror();

	strcpy(name, "conntrack_register_");
	strcat(name, conntrack_name);

	int (*register_my_conntrack) (struct conntrack_reg *);

	
	register_my_conntrack = dlsym(handle, name);
	if (!register_my_conntrack) {
		dprint("Error when finding symbol %s. Could not load conntrack !\n", conntrack_name);
		return -1;
	}

	struct conntrack_reg *my_conntrack = malloc(sizeof(struct conntrack_reg));
	bzero(my_conntrack, sizeof(struct conntrack_reg));

	
	if (!(*register_my_conntrack) (my_conntrack)) {
		dprint("Error while loading conntrack %s. Could not load conntrack !\n", conntrack_name);
		return -1;
	}

	conntracks[id] = malloc(sizeof(struct conntrack_reg));
	memcpy(conntracks[id], my_conntrack, sizeof(struct conntrack_reg));
	conntracks[id]->dl_handle = handle;

	dprint("Conntrack %s registered\n", conntrack_name);


	return id;


}

int conntrack_add_target_priv(int target_type, void *priv, struct rule_node *n, void* frame) {

	__u32 hash;
	hash = conntrack_hash(n, frame);

	struct conntrack_entry *ce;
	ce = conntrack_get_entry(hash, n, frame);

	struct conntrack_privs *cp;

	if (!ce) {
		ce = malloc(sizeof(struct conntrack_entry));
		bzero(ce, sizeof(struct conntrack_entry));
		ce->next = ct_table[hash];
		ct_table[hash] = ce;

		struct match *m = n->match;
		// TODO : add matches in the opposite direction for speed
		while (m) {
			if (conntracks[m->match_type] && conntracks[m->match_type]->alloc_match_priv) {
				int start = 0;
				if (m->prev)
					start = m->prev->next_start;
				void *priv = (*conntracks[m->match_type]->alloc_match_priv) (frame, start);
				cp = malloc(sizeof(struct conntrack_privs));
				cp->priv_type = m->match_type;
				cp->priv = priv;
				cp->next = ce->match_privs;
				ce->match_privs = cp;
			}
			m = m->next;
		}
	}

	cp = ce->target_privs;

	while (cp) {
		if (cp->priv_type == target_type) {
			dprint("Warning. Target priv already added\n");
			return 0;
		}
		cp = cp->next;
	}

	cp = malloc(sizeof(struct conntrack_privs));

	cp->next = ce->target_privs;
	ce->target_privs = cp;

	cp->priv_type = target_type;
	cp->priv = priv;
	
	
	return 1;
}


void *conntrack_get_target_priv(int target_type, struct rule_node *n, void *frame) {


	__u32 hash;
	hash = conntrack_hash(n, frame);

	struct conntrack_entry *ce;
	ce = conntrack_get_entry(hash, n, frame);

	if (!ce)
		return NULL;

	struct conntrack_privs *cp;
	cp = ce->target_privs;
	while (cp) {
		if (cp->priv_type == target_type) {
			return cp->priv;
		}
		cp = cp->next;
	}

	return NULL;
}

int conntrack_remove_target_priv(int target_type, struct rule_node *n, void *frame) {

	__u32 hash;
	hash = conntrack_hash(n, frame);

	struct conntrack_entry *ce;
	ce = conntrack_get_entry(hash, n, frame);

	struct conntrack_privs *cp, *cp_prev;
	cp = ce->target_privs;
	cp_prev = NULL;

	// Remove the target priv
	while (cp) {
		if (cp->priv_type == target_type) {
			if (!cp_prev)
				ce->target_privs = cp->next;
			else
				cp_prev->next = cp->next;
			
			free(cp);
			break;
		}
		cp_prev = cp;
		cp = cp->next;
	}
	
	// If there are no target priv, we can remove this connection tracking entry
	if (!ce->target_privs) {
		cp = ce->match_privs;
		while (cp) {
			if (conntracks[cp->priv_type]->cleanup_match_priv)
				(*conntracks[cp->priv_type]->cleanup_match_priv) (cp->priv);

			cp_prev = cp;
			cp = cp->next;
			free(cp_prev);
		}
		
		ce->match_privs = NULL;
		ce->target_privs = NULL;
	}

	ce = ct_table[hash];

	struct conntrack_entry *ce_prev = NULL;
	while (ce) {

		if (!ce->match_privs) {
			if (!ce_prev) 
				ct_table[hash] = ce->next;
			else
				ce_prev->next = ce->next;

		}
		
		ce_prev = ce;
		ce = ce->next;
	}
	
	return 1;
}


__u32 conntrack_hash(struct rule_node *n, void *frame) {


	struct match *m;
	m = n->match;

	// Compute our hash for each layer
	__u32 hash, res;
	hash = INITVAL;
	while (m) {

		if (conntracks[m->match_type]) {
			int start = node_find_header_start(n, m->match_type);
			res = (*conntracks[m->match_type]->get_hash) (frame, start);
			hash = jhash_2words(hash, res, INITVAL);

		}
		m = m->next;
	}

	hash %= CONNTRACK_SIZE;

	return hash;
}

struct conntrack_entry *conntrack_get_entry(__u32 hash, struct rule_node *n, void *frame) {
	
	// Doublecheck that we are talking about the right thing

	struct conntrack_entry *ce;
	ce = ct_table[hash];

	if (!ce)
		return NULL;
		
	struct conntrack_privs *cp;
	cp = ce->match_privs;

	while (cp) {
		int start = node_find_header_start(n, cp->priv_type);
		if (!(*conntracks[cp->priv_type]->doublecheck) (frame, start, cp->priv)) {
			ce = ce->next; // If it's not the right conntrack entry, go to next one
			if (!ce)
				return NULL; // No entry matched
			cp = ce->match_privs;
			continue;
		}

		cp = cp->next;
	}

	return ce;

}
