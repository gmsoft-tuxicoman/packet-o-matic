
#include <sys/time.h>
#include "match_rtp.h"
#include "conntrack_rtp.h"

#define INITVAL 0x83f0e1b6

#define RTP_TIMEOUT 10 // sec 10 of timeout for rtp connections

struct conntrack_functions *ct_functions;

int conntrack_register_rtp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs) {
	
	r->get_hash = conntrack_get_hash_rtp;
	r->doublecheck = conntrack_doublecheck_rtp;
	r->alloc_match_priv = conntrack_alloc_match_priv_rtp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_rtp;

	ct_functions = ct_funcs;
	
	return 1;
}


__u32 conntrack_get_hash_rtp(void *frame, unsigned int start) {

	struct rtphdr* hdr;
	
	hdr = frame + start;	

	// Compute the hash

	__u32 rtp_hash = jhash_1word(hdr->ssrc, INITVAL);
	ndprint("SSRC = 0x%x, start %u\n", hdr->ssrc, start);


	return rtp_hash;

}

int conntrack_doublecheck_rtp(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce) {

	

	struct rtphdr* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_rtp *p;
	p = priv;

	if (p->ssrc != hdr->ssrc || p->payload_type != hdr->payload_type)
		return 0;

	// Remove the timer from the queue
	(*ct_functions->dequeue_timer) (p->timer);

	// And requeue it at the end
	(*ct_functions->queue_timer) (p->timer, RTP_TIMEOUT);


	return 1;
}


void *conntrack_alloc_match_priv_rtp(void *frame, unsigned int start, struct conntrack_entry *ce) {
	
	struct rtphdr* hdr;
	hdr = frame + start;
	

	// Allocate the rtp priv
	struct conntrack_priv_rtp *priv;
	priv = malloc(sizeof(struct conntrack_priv_rtp));
	bzero(priv, sizeof(struct conntrack_priv_rtp));
	ndprint("CONNTRACK SSRC 0x%x, start %u\n", hdr->ssrc, start);
	priv->ssrc = hdr->ssrc;
	priv->payload_type = hdr->payload_type;


	// Allocate the timeout and set it up
	struct conntrack_timer *t;
	t = (*ct_functions->alloc_timer) (ce);

	priv->timer = t;

	// Put the timeout at the end of the list

	(*ct_functions->queue_timer) (t, RTP_TIMEOUT);

	return priv;

}

int conntrack_cleanup_match_priv_rtp(void *priv) {

	struct conntrack_priv_rtp *p = priv;

	if (p->timer) {
		(*ct_functions->dequeue_timer) (p->timer);
		(*ct_functions->cleanup_timer) (p->timer);
	}

	free(priv);
	return 1;
}

