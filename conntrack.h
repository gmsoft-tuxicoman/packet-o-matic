
#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

#include "common.h"

#include <linux/jhash.h>

struct conntrack_entry {

	__u32 hash;
	struct conntrack_entry *next;
	struct conntrack_privs *match_privs;
	struct conntrack_privs *target_privs;

};

struct conntrack_reg {

	void *dl_handle;
	__u32 (*get_hash) (void* frame, unsigned int);
	int (*doublecheck) (void *frame, unsigned int start, void *priv);
	void* (*alloc_match_priv) (void *frame, unsigned int start, struct conntrack_entry *ce);
	int (*cleanup_match_priv) (void *priv);
	int (*conntrack_do_timeouts) (int (*conntrack_close_connection)(struct conntrack_entry *ce));


};

struct conntrack_privs {

	struct conntrack_privs *next;
	int priv_type;
	void *priv;

};

int conntrack_init();
int conntrack_register(const char *name);
int conntrack_add_target_priv(struct target*, void *priv, struct rule_node *n, void* frame);
void *conntrack_get_target_priv(struct target*, struct rule_node *n, void *frame);
__u32 conntrack_hash(struct rule_node *n, void *frame);
struct conntrack_entry *conntrack_get_entry(__u32 hash, struct rule_node *n, void *frame);
int conntrack_cleanup();
int conntrack_unregister_all();
int conntrack_do_timeouts();
#endif
