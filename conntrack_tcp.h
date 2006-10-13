
#ifndef __CONNTRACK_TCP_H__
#define __CONNTRACK_TCP_H__


#include "modules_common.h"
#include "conntrack.h"


struct conntrack_priv_tcp {

	__u16 sport;
	__u16 dport;
	struct conntrack_timer *timer;
	int state;

};

int conntrack_register_tcp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs);
__u32 conntrack_get_hash_tcp(void *frame, unsigned int start);
int conntrack_doublecheck_tcp(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce);
void *conntrack_alloc_match_priv_tcp(void *frame, unsigned int start, struct conntrack_entry *ce);
int conntrack_cleanup_match_priv_tcp(void *priv);


int conntrack_tcp_update_timer(struct conntrack_priv_tcp *priv, struct tcphdr *hdr);

#endif

