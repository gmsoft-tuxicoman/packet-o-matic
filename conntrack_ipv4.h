
#ifndef __CONNTRACK_IPV4_H__
#define __CONNTRACK_IPV4_H__


#include "common.h"
#include "conntrack.h"

int conntrack_register_ipv4();

__u32 conntrack_get_id_ipv4(struct rule_match *m, void *frame, unsigned int len, u32 init);



#endif

