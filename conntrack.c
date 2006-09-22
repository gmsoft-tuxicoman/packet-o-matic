
#include <signal.h>

#include "conntrack.h"

#define MAX_CONNTRACK 16

#define CONNTRACK_SIZE 65535

#define INITVAL 0xdf92b6eb


struct conntrack_reg *conntracks[MAX_CONNTRACK];
struct conntrack_entry *ct_table[CONNTRACK_SIZE];

void conntrack_timeout_handler(int signal) {

	ndprint("Looking for timeouts ...\n");
	conntrack_do_timeouts();

}

int conntrack_init() {

	int i;
	
	for (i = 0; i < CONNTRACK_SIZE; i ++)
		ct_table[i] = NULL;


	signal(SIGALRM, conntrack_timeout_handler);
	
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

	conntracks[id] = my_conntrack;
	conntracks[id]->dl_handle = handle;

	dprint("Conntrack %s registered\n", conntrack_name);


	return id;


}

int conntrack_add_target_priv(struct target *t, void *priv, struct rule_node *n, void* frame) {

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
		ce->hash = hash;

		struct match *m = n->match;
		// TODO : add matches in the opposite direction for speed
		while (m) {
			if (conntracks[m->match_type] && conntracks[m->match_type]->alloc_match_priv) {
				int start = 0;
				if (m->prev)
					start = m->prev->next_start;
				void *priv = (*conntracks[m->match_type]->alloc_match_priv) (frame, start, ce);
				cp = malloc(sizeof(struct conntrack_privs));
				cp->priv_type = m->match_type;
				cp->priv = priv;
				cp->next = ce->match_privs;
				ce->match_privs = cp;
			}
			m = m->next;
		}
	}

	// Let's see if that priv_type is already present

	cp = ce->target_privs;

	while (cp) {
		if (cp->priv_type == t->target_type) {
			dprint("Warning. Target priv already added\n");
			return 0;
		}
		cp = cp->next;
	}

	// Ok it's not. Creating a new conntrack_priv for our target

	cp = malloc(sizeof(struct conntrack_privs));
	bzero(cp, sizeof(struct conntrack_privs));

	cp->next = ce->target_privs;
	ce->target_privs = cp;

	cp->priv_type = t->target_type;
	cp->priv = priv;

	
	return 1;
}


void *conntrack_get_target_priv(struct target *t, struct rule_node *n, void *frame) {


	__u32 hash;
	hash = conntrack_hash(n, frame);

	struct conntrack_entry *ce;
	ce = conntrack_get_entry(hash, n, frame);

	if (!ce)
		return NULL;

	struct conntrack_privs *cp;
	cp = ce->target_privs;
	while (cp) {
		if (cp->priv_type == t->target_type) {
			return cp->priv;
		}
		cp = cp->next;
	}

	return NULL;
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
int conntrack_close_connnection (struct conntrack_entry *ce) {


	struct conntrack_privs *p, *tmp;
	p = ce->target_privs;
	while (p) {
		if (p->priv)
			target_close_connection(p->priv_type, p->priv);
		tmp = p;
		p = p->next;
		free(tmp);

	}

	// Ok this connection is closed. let's remove it

	// Remove the match privs
	p = ce->match_privs;
	while (p) {
		if (conntracks[p->priv_type] && conntracks[p->priv_type]->cleanup_match_priv)
			(*conntracks[p->priv_type]->cleanup_match_priv) (p->priv);

		tmp = p;
		p = p->next;
		free(tmp);
	}

	// Free the conntrack_entry itself
	

	if (ct_table[ce->hash] == ce) {
		ct_table[ce->hash] = ce->next;
	} else {
		struct conntrack_entry *tmpce;
		tmpce = ct_table[ce->hash];
		while (tmpce->next) {
			if (tmpce->next == ce) {
				tmpce->next = ce->next;
				break;
			}
			tmpce = tmpce->next;
		}
	}
	
	free (ce);


	return 1;
}

int conntrack_cleanup() {

	int i;

	for (i = 0; i < CONNTRACK_SIZE; i ++) {
		while (ct_table[i]) {
			conntrack_close_connnection(ct_table[i]);
		}
	}

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

int conntrack_do_timeouts() {

	int i;
	
	for (i = 0; i < MAX_CONNTRACK; i++ ) {

		if (conntracks[i] && conntracks[i]->conntrack_do_timeouts) {
			(*conntracks[i]->conntrack_do_timeouts) (conntrack_close_connnection);
		}
	}

	return 1;
}


