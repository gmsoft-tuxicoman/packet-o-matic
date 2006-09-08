
#include "conntrack.h"

#define MAX_CONNTRACK 255

#define CONNTRACK_SIZE 65535

#define INITVAL 0xdf92b6eb

struct conntrack_reg *conntracks[MAX_CONNTRACK];
struct conntrack_entry ct_table[CONNTRACK_SIZE];


int conntrack_register(const char *conntrack_name) {


	int id;
	id = match_get_type(conntrack_name);
	if (id == -1) {
		dprint("Unable to register conntrack %s. Corresponding match not found\n", name);
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
	conntracks[id]->conntrack_name = malloc(strlen(conntrack_name) + 1);
	strcpy(conntracks[id]->conntrack_name, conntrack_name);
	conntracks[id]->dl_handle = handle;

	dprint("Conntrack %s registered\n", conntrack_name);


	return id;


}

struct conntrack *conntrack_alloc(int conntrack_type) {

	if (!conntracks[conntrack_type]) {
		dprint("Input type %u is not registered\n", conntrack_type);
		return NULL;
	}
	struct conntrack *i = malloc(sizeof(struct conntrack));
	i->conntrack_type = conntrack_type;
	t->get_priv = conntrack_get_priv;
	t->add_priv = conntrack_add_priv;
	t->remove_priv = conntrack_remove_priv;
	
	if (conntracks[conntrack_type]->init)
		if (!(*conntracks[conntrack_type]->init) (i)) {
			free(i);
			return NULL;
		}
	
	return i;
}

void *conntrack_get_target_priv(int conntrack_type, struct rule_node *n) {



	return NULL;
}

void conntrack_add_target_priv(int conntrack_type, void *priv) {

	struct conntrack_priv *p;
	p = conntrack_get_priv(id, priv_type);

	if (!p) {
		p = malloc(sizeof(struct conntrack_priv));
		p->ct_priv_type = priv_type;
	}
	
	p->priv = priv;

	return ;
}

__u32 conntrack_hash(struct rule_node *n, void *frame) {


	struct match *m;
	m = n->match;

	// Compute our hash for each layer
	__u32 hash, res;
	hash = INITVAL;
	while (m) {

		if (conntracks[m->match_type]) {
			int start = node_find_header_start(*n, cp->conntrack_type);
			res = (*conntracks[m->match_type]->get_hash) (frame, start);
			hash = jhash_2words(hash, res, INITVAL);

		}
		m = m->next;
	}

	hash %= CONNTRACK_SIZE;
	
	return hash;
}

struct conntrack_entry *conntrack_get_entry(__u32 hash, struct rule_node *n, frame) {
	
	// Doublecheck that we are talking about the right thing

	struct conntrack_entry *ce;
	ce = conntracks[hash];
		
	struct conntrack_privs *cp;
	cp = ce->match_privs;

	while (cp) {
		int start = node_find_header_start(*n, cp->conntrack_type);
		if (!(*conntracks[cp->priv_type]->doublecheck) (frame, start, cp->priv)) {
			ce = ce->next; // If it's not the right conntrack entry, go to next one
			dprint("Collision detected\n");
			if (!ce)
				return NULL; // No entry matched
			cp = ce->match_privs;
			continue;
		}

		cp = cp->next;
	}

	return hash;

}
