

#ifndef __TARGET_H__
#define __TARGET_H__

#include "common.h"

struct target {
	int target_type;
	void *target_priv;
	char **params_value;
	int (*match_register) (const char *);
	int (*conntrack_add_priv) (struct target* t, void *priv, struct rule_node *n, void* frame);
	void* (*conntrack_get_priv) (struct target *t, struct rule_node *n, void *frame);

};

struct target_reg {
	char *target_name;
	void *dl_handle;
	char **params_name;
	char **params_help;
	int (*init) (struct target*);
	int (*open) (struct target*);
	int (*process) (struct target*, struct rule_node*, void*, unsigned int);
	int (*close_connection) (void *);
	int (*close) (struct target *t);
	int (*cleanup) (struct target *t);
};
	

int target_register(const char *target_name);
struct target *target_alloc(int target_type);
int target_set_param(struct target *t, char *name, char* value);
int target_open(struct target *t);
int target_process(struct target *t, struct rule_node *node, unsigned char *buffer, unsigned int bufflen);
int target_close_connection(int target_type, void *conntrack_privs);
int target_close(struct target *t);
int target_cleanup(struct target *t);
int target_unregister_all();
void target_print_help();


#endif
