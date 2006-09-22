
#include <netinet/udp.h>
#include <sys/time.h>

#include "conntrack_udp.h"

#define INITVAL 0x7513adf4

#define UDP_TIMEOUT 180 // 180 sec of timeout for udp connections

struct conntrack_udp_timeout *timeouts; // Head of the timeout list
struct conntrack_udp_timeout *timeouts_tail; // Tail of the timeout list

/*
void check_list (struct conntrack_udp_timeout *t) {

	if (t->prev != NULL)
		dprint("t->prev != NULL\n");


	struct conntrack_udp_timeout *prev;
	prev = t;
	t = t->next;
	while (t) {
		
		if (!t->next)
			if (t != timeouts_tail)
				dprint("Tail not set correctly\n");
		// else 
			//if (t->next->prev != t)
			//	dprint("Prev not set correctly for 0x%x (0x%x)\n", (unsigned) t->next, (unsigned) t->next->prev);

		t = t->next;

	}
	
} */


int conntrack_register_udp(struct conntrack_reg *r) {
	
	r->get_hash = conntrack_get_hash_udp;
	r->doublecheck = conntrack_doublecheck_udp;
	r->alloc_match_priv = conntrack_alloc_match_priv_udp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_udp;
	r->conntrack_do_timeouts = conntrack_do_timeouts_udp;
	
	timeouts = NULL;
	timeouts_tail = NULL;
	
	return 1;
}


__u32 conntrack_get_hash_udp(void *frame, unsigned int start) {

	struct udphdr* hdr;
	
	hdr = frame + start;	

	// Compute the hash

	__u32 udp_hash = jhash_1word((hdr->source << 16) |  hdr->dest, INITVAL);


	return udp_hash;

}

int conntrack_doublecheck_udp(void *frame, unsigned int start, void *priv) {

	

	struct udphdr* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_udp *p;
	p = priv;
	
	if (p->sport != hdr->source || p->dport != hdr->dest)
		return 0;

	// Update the timeout of the connection
	
	struct conntrack_udp_timeout *t, *tmp;
	t = p->timeout;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	t->expires = tv.tv_sec + UDP_TIMEOUT;

	if (t == timeouts_tail)
		return 1;
	// Remove is from the list

	if (t == timeouts) {
		timeouts = timeouts->next;
		timeouts->prev = NULL;
	} else {
		tmp = t->prev;
		tmp->next = t->next;
		tmp->next->prev = tmp;
	}


	// Put it at the end
	t->prev = timeouts_tail;
	timeouts_tail->next = t;
	t->next = NULL;
	timeouts_tail = t;
	

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
	struct conntrack_udp_timeout *t;
	t = malloc(sizeof(struct conntrack_udp_timeout));
	bzero(t, sizeof(struct conntrack_udp_timeout));

	struct timeval tv;
	gettimeofday(&tv, NULL);
	t->expires = tv.tv_sec + UDP_TIMEOUT;
	t->ce = ce;

	priv->timeout = t;

	// Put the timeout at the end of the list
	
	ndprint("Addding 0x%x to the list\n", (unsigned) t);
	
	if (timeouts == NULL) {
		timeouts = t;
		timeouts_tail = t;
	} else {
		t->prev = timeouts_tail;
		timeouts_tail->next = t;
		timeouts_tail = t;
	}


	return priv;

}

int conntrack_cleanup_match_priv_udp(void *priv) {

	struct conntrack_priv_udp *p = priv;
	
	struct conntrack_udp_timeout *tmp;
	tmp = p->timeout;

	if (tmp) {

		if (tmp->prev)
			tmp->prev->next = tmp->next;
		else
			timeouts = tmp->next;

		if (tmp->next)
			tmp->next->prev = tmp->prev;
		else
			timeouts_tail = tmp->prev;


		free(p->timeout);
	}

	free(priv);
	return 1;
}

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


