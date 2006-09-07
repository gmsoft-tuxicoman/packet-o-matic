
#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

#include "common.h"

#include <linux/jhash.h>




struct conntrack_reg {

	int ct_type;
	__u32 (*get_id) (struct rule_match*, void*, unsigned int, u32);

};

int conntrack_register(struct conntrack_reg *r, const char *name);

void *conntrack_get_priv(__u32 id, int priv_type);

void conntrack_add_priv(__u32 id, int priv_type, void *priv);

__u32 conntrack_get_id(int ct_type, struct rule_match *m, void *frame, unsigned int len, u32 init);

#endif
