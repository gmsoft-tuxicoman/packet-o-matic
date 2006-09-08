
#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

#include <linux/jhash.h>

#include "common.h"


struct conntrack {

	void *conntrack_priv;
	void* (*get_priv) (int);
	void (*add_priv) (int);
	void (*remove_priv) (int);

};

struct conntrack_reg {

	int ct_type;
	void *dl_handle;
	int (*init) (struct conntrack *c);
	__u32 (*get_hash) (struct match* m, void* frame, unsigned int);
	int (*doublecheck) (struct conntrack *c);
	int (*cleanup) (struct conntrack *c);

};

struct conntrack_privs {

	struct conntrack_privs *next;
	int priv_type;
	void *priv;

};

struct conntrack_entry {

	struct conntrack_entry *next;
	struct conntrack_privs *match_privs;
	struct conntrack_privs *target_privs;

};

int conntrack_register(struct conntrack_reg *r, const char *name);
struct conntrack *conntrack_alloc(int conntrack_type);
void *conntrack_get_priv(int priv_type);
void conntrack_add_priv(int priv_type, void *priv);
void conntrack_remove_priv(int priv_type);
int conntrack_cleanup(struct conntrack *c);
int conntrack_unregister_all();

#endif
