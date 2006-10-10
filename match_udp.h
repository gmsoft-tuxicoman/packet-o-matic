
#ifndef __MATCH_UDP_H__
#define __MATCH_UDP_H__


#include "modules_common.h"
#include "match.h"

struct match_priv_udp {

	unsigned short sport_min;
	unsigned short sport_max;
	unsigned short dport_min;
	unsigned short dport_max;

};


int match_register_udp();

int match_register_udp();
int match_init_udp(struct match *m);
int match_reconfig_udp(struct match *m);
int match_eval_udp(struct match* match, void* frame, unsigned int start, unsigned int len);
int match_cleanup_udp(struct match *m);


#endif
