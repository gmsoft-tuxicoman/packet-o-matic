
#include <netinet/udp.h>
#include <sys/time.h>

#include "conntrack_udp.h"

#define INITVAL 0x7513adf4

#define UDP_TIMEOUT 180 // 180 sec of timeout for udp connections

struct conntrack_functions *ct_functions;


int conntrack_register_udp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs) {
	
	r->get_hash = conntrack_get_hash_udp;
	r->doublecheck = conntrack_doublecheck_udp;
	r->alloc_match_priv = conntrack_alloc_match_priv_udp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_udp;
	
	ct_functions = ct_funcs;
	
	return 1;
}


__u32 conntrack_get_hash_udp(void *frame, unsigned int start) {

	struct udphdr* hdr;
	
	hdr = frame + start;	

	// Compute the hash

	__u32 udp_hash = jhash_1word((hdr->source << 16) |  hdr->dest, INITVAL);


	return udp_hash;

}

int conntrack_doublecheck_udp(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce) {

	

	struct udphdr* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_udp *p;
	p = priv;
	
	if (p->sport != hdr->source || p->dport != hdr->dest)
		return 0;


	// Remove the timer from the queue
	(*ct_functions->dequeue_timer) (p->timer);

	// And requeue it at the end
	(*ct_functions->queue_timer) (p->timer, UDP_TIMEOUT);

	return 1;
}


void *conntrack_alloc_match_priv_udp(void *frame, unsigned int start, struct conntrack_entry *ce) {
	
	struct udphdr* hdr;
	hdr = frame + start;
	

	// Allocate the udp priv
	struct conntrack_priv_udp *priv;
	priv = malloc(sizeof(struct conntrack_priv_udp));
	bzero(priv, sizeof(struct conntrack_priv_udp));
	priv->sport = hdr->source;
	priv->dport = hdr->dest;


	// Allocate the timeout and set it up
	struct conntrack_timer *t;
	t = (*ct_functions->alloc_timer) (ce);

	priv->timer = t;

	// Put the timeout at the end of the list
	
	(*ct_functions->queue_timer) (t, UDP_TIMEOUT);

	return priv;

}

int conntrack_cleanup_match_priv_udp(void *priv) {

	struct conntrack_priv_udp *p = priv;
	
	if (p->timer) {
		(*ct_functions->dequeue_timer) (p->timer);
		(*ct_functions->cleanup_timer) (p->timer);
	}

	free(priv);
	return 1;
}
/*
int conntrack_do_timeouts_udp(int (*conntrack_close_connection) (struct conntrack_entry *ce)) {

	struct timeval tv;
	gettimeofday(&tv, NULL);

	while (timeouts && tv.tv_sec >= timeouts->expires) {

		struct conntrack_entry *ce;
		ce = timeouts->ce;
		ndprint("Connection 0x%x expired\n", (unsigned) ce);

		(*conntrack_close_connection) (ce);

	}

	return 1;
}

*/
