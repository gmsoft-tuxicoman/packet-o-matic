
#ifndef __CONNTRACK_RTP_H__
#define __CONNTRACK_RTP_H__


#include "modules_common.h"
#include "conntrack.h"

struct conntrack_priv_rtp {

	__u32 ssrc;
	__u8 payload_type;
	struct conntrack_timer *timer;

};

int conntrack_register_rtp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs);
__u32 conntrack_get_hash_rtp(void *frame, unsigned int start);
int conntrack_doublecheck_rtp(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce);
void *conntrack_alloc_match_priv_rtp(void *frame, unsigned int start, struct conntrack_entry *ce);
int conntrack_cleanup_match_priv_rtp(void *priv);
int conntrack_do_timeouts_rtp( int (*conntrack_close_connection) (struct conntrack_entry *ce));

#endif

