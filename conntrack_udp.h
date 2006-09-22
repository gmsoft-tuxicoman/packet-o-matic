
#ifndef __CONNTRACK_UDP_H__
#define __CONNTRACK_UDP_H__


#include "modules_common.h"
#include "conntrack.h"

struct conntrack_udp_timeout {

	time_t expires;
	struct conntrack_entry *ce;
	struct conntrack_udp_timeout *next;
	struct conntrack_udp_timeout *prev;

};

struct conntrack_priv_udp {

	__u16 sport;
	__u16 dport;
	struct conntrack_udp_timeout *timeout;

};

int conntrack_register_udp(struct conntrack_reg *r);
__u32 conntrack_get_hash_udp(void *frame, unsigned int start);
int conntrack_doublecheck_udp(void *frame, unsigned int start, void *priv);
void *conntrack_alloc_match_priv_udp(void *frame, unsigned int start, struct conntrack_entry *ce);
int conntrack_cleanup_match_priv_udp(void *priv);
int conntrack_do_timeouts_udp( int (*conntrack_close_connection) (struct conntrack_entry *ce));

#endif

