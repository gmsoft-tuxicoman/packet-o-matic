
#ifndef __MATCH_TCP_H__
#define __MATCH_TCP_H__


#include "modules_common.h"
#include "match.h"


struct match_priv_tcp {

	unsigned short sport_min;
	unsigned short sport_max;
	unsigned short dport_min;
	unsigned short dport_max;

};


int match_register_tcp();
int match_init_tcp(struct match *m);
int match_config_tcp(struct match *m, void *params);
int match_eval_tcp(struct match* match, void* frame, unsigned int start, unsigned int len);
int match_cleanup_tcp(struct match *m);

#endif
