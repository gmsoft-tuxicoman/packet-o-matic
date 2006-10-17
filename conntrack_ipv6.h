
#ifndef __CONNTRACK_IPV6_H__
#define __CONNTRACK_IPV6_H__


#include "modules_common.h"
#include "conntrack.h"

struct conntrack_priv_ipv6 {

	struct in6_addr saddr;
	struct in6_addr daddr;

};

int conntrack_register_ipv6(struct conntrack_reg *r, struct conntrack_functions *ct_funcs);
__u32 conntrack_get_hash_ipv6(void *frame, unsigned int start);
int conntrack_doublecheck_ipv6(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce);
void *conntrack_alloc_match_priv_ipv6(void *frame, unsigned int start, struct conntrack_entry *ce);
int conntrack_cleanup_match_priv_ipv6(void *priv);


#endif

