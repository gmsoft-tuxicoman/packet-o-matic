

#ifndef __TARGET_H__
#define __TARGET_H__

#include "common.h"

struct target {
	int target_type;
	void *target_priv;
	int (*match_register) (const char *);
	int (*conntrack_add_priv) (int target_type, void *priv, struct rule_node *n, void* frame);
	void* (*conntrack_get_priv) (int target_type, struct rule_node *n, void *frame);
	int (*conntrack_remove_priv) (int target_type, struct rule_node *n, void *frame);

};

struct target_reg {
	char *target_name;
	void *dl_handle;
	int (*init) (struct target*);
	int (*open) (struct target*, const char *params);
	int (*process) (struct target*, struct rule_node*, void*, unsigned int);
	int (*close) (struct target *t);
	int (*cleanup) (struct target *t);
};
	

int target_register(const char *target_name);
struct target *target_alloc(int target_type);
int target_open(struct target *t, const char *params);
int target_process(struct target *t, struct rule_node *node, unsigned char *buffer, unsigned int bufflen);
int target_close(struct target *t);
int target_cleanup(struct target *t);
int target_unregister_all();


#endif
