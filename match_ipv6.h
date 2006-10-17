
#ifndef __MATCH_IPV6_H__
#define __MATCH_IPV6_H__


#include "modules_common.h"
#include "match.h"


struct match_priv_ipv6 {

	struct in6_addr saddr;
	unsigned char snetmask;
	struct in6_addr daddr;
	unsigned char dnetmask;
};


int match_register_ipv6();
int match_init_ipv6(struct match *m);
int match_reconfig_ipv6(struct match *m);
int match_eval_ipv6(struct match* match, void* frame, unsigned int start, unsigned int len);
int match_cleanup_ipv6(struct match *m);


#endif
