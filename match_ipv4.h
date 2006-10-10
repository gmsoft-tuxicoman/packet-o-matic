
#ifndef __MATCH_IPV4_H__
#define __MATCH_IPV4_H__


#include "modules_common.h"
#include "match.h"


struct match_priv_ipv4 {

	struct in_addr saddr;
	struct in_addr snetmask;
	struct in_addr daddr;
	struct in_addr dnetmask;
	unsigned int proto;
	unsigned int proto_mask;
};


int match_register_ipv4();
int match_init_ipv4(struct match *m);
int match_reconfig_ipv4(struct match *m);
int match_eval_ipv4(struct match* match, void* frame, unsigned int start, unsigned int len);
int match_cleanup_ipv4(struct match *m);


#endif
