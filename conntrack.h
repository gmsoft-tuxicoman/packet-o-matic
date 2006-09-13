
#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

#include "common.h"

#include <linux/jhash.h>

struct conntrack {

	void *conntrack_priv;

	int (*add_target_priv) (int target_type, void *priv, struct rule_node *n, void* frame);
	void* (*get_target_priv) (int target_type, struct rule_node *n, void *frame);
	int (*remove_target_priv) (int target_type, struct rule_node *n, void *frame);

};

struct conntrack_reg {

	void *dl_handle;
	int (*init) (struct conntrack *c);
	__u32 (*get_hash) (void* frame, unsigned int);
	int (*doublecheck) (void *frame, unsigned int start, void *priv);
	void* (*alloc_match_priv) (void *frame, unsigned int start);
	int (*cleanup_match_priv) (void *priv);
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

int conntrack_init();
int conntrack_register(const char *name);
struct conntrack *conntrack_alloc(int conntrack_type);
int conntrack_add_target_priv(int target_type, void *priv, struct rule_node *n, void* frame);
void *conntrack_get_target_priv(int target_type, struct rule_node *n, void *frame);
int conntrack_remove_target_priv(int target_type, struct rule_node *n, void *frame);
__u32 conntrack_hash(struct rule_node *n, void *frame);
struct conntrack_entry *conntrack_get_entry(__u32 hash, struct rule_node *n, void *frame);
int conntrack_cleanup(struct conntrack *c);
int conntrack_unregister_all();

#endif