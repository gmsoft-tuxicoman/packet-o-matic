
#ifndef __MATCH_ETHERNET_H__
#define __MATCH_ETHERNET_H__

#include <linux/if_ether.h>

#include "modules_common.h"
#include "match.h"

struct match_priv_ethernet {

	unsigned char smac[6];
	unsigned char smac_mask[6];
	unsigned char dmac[6];
	unsigned char dmac_mask[6];
	unsigned char proto[2];
	unsigned char proto_mask[2];
	
};

int match_register_ethernet(struct match_reg *r);
int match_init_ethernet(struct match *m);
int match_config_ethernet(struct match *m, void *params);
int match_eval_ethernet(struct match* match, void* frame, unsigned int start, unsigned int len);
int match_cleanup_ethernet(struct match *m);


#endif
