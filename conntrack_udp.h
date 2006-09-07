
#ifndef __CONNTRACK_UDP_H__
#define __CONNTRACK_UDP_H__


#include "common.h"
#include "conntrack.h"

int conntrack_register_udp();

__u32 conntrack_get_id_udp(struct rule_match *m, void *frame, unsigned int len, u32 init);


#endif

