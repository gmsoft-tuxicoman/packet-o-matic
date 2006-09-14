
#ifndef __CONNTRACK_UDP_H__
#define __CONNTRACK_UDP_H__


#include "modules_common.h"
#include "conntrack.h"

struct conntrack_priv_tcp {

	__u16 sport;
	__u16 dport;

};

int conntrack_register_tcp(struct conntrack_reg *r);
__u32 conntrack_get_hash_tcp(void *frame, unsigned int start);
int conntrack_doublecheck_tcp(void *frame, unsigned int start, void *priv);
void *conntrack_alloc_match_priv_tcp(void *frame, unsigned int start);
int conntrack_cleanup_match_priv_tcp(void *priv);


#endif

