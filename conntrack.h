
#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

#include <linux/jhash.h>

#include "common.h"


struct conntrack {

	struct conntrack_priv *privs;

};

struct conntrack_reg {

	int ct_type;
	void *dl_handle;
	int (*init) (struct conntrack *c);
	__u32 (*get_layer_id) (struct match* m, void* frame, unsigned int);
	int (*doublecheck) (struct conntrack *c);
	int (*cleanup) (struct conntrack *c);

};

struct conntrack_priv {

	struct conntrack_priv *next;
	int ct_priv_type;
	void *priv;

};

int conntrack_register(struct conntrack_reg *r, const char *name);
struct conntrack *conntrack_alloc(int conntrack_type);
void *conntrack_get_priv(__u32 id, int priv_type);
void conntrack_add_priv(__u32 id, int priv_type, void *priv);
void conntrack_remove_priv(__u32 id, int priv_type, void *priv);
int conntrack_cleanup(struct conntrack *c);
int conntrack_unregister_all();

#endif
