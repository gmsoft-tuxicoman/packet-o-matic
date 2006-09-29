
#ifndef __CONNTRACK_UDP_H__
#define __CONNTRACK_UDP_H__


#include "modules_common.h"
#include "conntrack.h"


struct conntrack_priv_udp {

	__u16 sport;
	__u16 dport;
	struct conntrack_timer *timer;

};

int conntrack_register_udp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs);
__u32 conntrack_get_hash_udp(void *frame, unsigned int start);
int conntrack_doublecheck_udp(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce);
void *conntrack_alloc_match_priv_udp(void *frame, unsigned int start, struct conntrack_entry *ce);
int conntrack_cleanup_match_priv_udp(void *priv);
int conntrack_do_timeouts_udp( int (*conntrack_close_connection) (struct conntrack_entry *ce));

#endif

