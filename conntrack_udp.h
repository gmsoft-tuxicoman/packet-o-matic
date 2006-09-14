
#ifndef __CONNTRACK_UDP_H__
#define __CONNTRACK_UDP_H__


#include "modules_common.h"
#include "conntrack.h"

struct conntrack_priv_udp {

	__u16 sport;
	__u16 dport;

};

int conntrack_register_udp(struct conntrack_reg *r);
__u32 conntrack_get_hash_udp(void *frame, unsigned int start);
int conntrack_doublecheck_udp(void *frame, unsigned int start, void *priv);
void *conntrack_alloc_match_priv_udp(void *frame, unsigned int start);
int conntrack_cleanup_match_priv_udp(void *priv);


#endif

