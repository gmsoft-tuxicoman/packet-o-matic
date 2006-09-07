
#include "conntrack.h"

#define MAX_CONNTRACK 255

#define CONNTRACK_SIZE 65535



struct conntrack_reg *conntracks[MAX_CONNTRACK];
struct conntrack_entry ct_table[CONNTRACK_SIZE];


int conntrack_register(struct conntrack_reg *r, const char *name) {

	int id;
	id = match_get_type(name);
	if (id == -1) {
		dprint("Unable to register conntrack %s. Corresponding match not found\n", name);
		return -1;
	}

	if (conntracks[id])
		return id;
	
	dprint("Registering conntrack %s ...\n", name);
	conntracks[id] = malloc(sizeof(struct conntrack_reg));
	memcpy(conntracks[id], r, sizeof(struct conntrack_reg));
	return id;
}

void *conntrack_get_priv(__u32 id, int priv_type) {
	
	struct conntrack_priv *p;
	p = ct_table[id].privs;

	while (p) {
		if (p->ct_priv_type == priv_type)
			return p->priv;
		p = p->next;
	}

	return NULL;
}

void conntrack_add_priv(__u32 id, int priv_type, void *priv) {

	struct conntrack_priv *p;
	p = conntrack_get_priv(id, priv_type);

	if (!p) {
		p = malloc(sizeof(struct conntrack_priv));
		p->ct_priv_type = priv_type;
	}
	
	p->priv = priv;

	return ;
}

__u32 conntrack_get_id(int ct_type, struct rule_match *m, void *frame, unsigned int len, u32 init) {

	if (!conntracks[ct_type] || !conntracks[ct_type]->get_id) {
		init %= CONNTRACK_SIZE;
		return init;
	}

	return (*conntracks[ct_type]->get_id) (m, frame, len, init);

}


