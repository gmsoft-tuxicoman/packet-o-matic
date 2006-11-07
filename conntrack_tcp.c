/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


#include <netinet/tcp.h>

#include "conntrack_tcp.h"

#define INITVAL 0x84fa0b2c

#define TCP_SYN_SENT_T	2 * 60
#define TCP_SYN_RECV_T	60
#define TCP_CLOSE_T	60
#define TCP_ESTABLISHED_T 2 * 60 * 60

struct conntrack_functions *ct_functions;

int conntrack_register_tcp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs) {
	
	r->get_hash = conntrack_get_hash_tcp;
	r->doublecheck = conntrack_doublecheck_tcp;
	r->alloc_match_priv = conntrack_alloc_match_priv_tcp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_tcp;

	ct_functions = ct_funcs;
	
	return 1;
}


__u32 conntrack_get_hash_tcp(void *frame, unsigned int start) {

	struct tcphdr* hdr;
	
	hdr = frame + start;	

	// Compute the hash

	__u32 tcp_hash = jhash_1word((hdr->source << 16) |  hdr->dest, INITVAL);


	return tcp_hash;

}

int conntrack_tcp_update_timer(struct conntrack_priv_tcp *priv, struct tcphdr *hdr) {

	if (hdr->syn && hdr->ack) {
		priv->state = TCP_SYN_RECV;
		(*ct_functions->queue_timer) (priv->timer, TCP_SYN_RECV_T);
	} else if (hdr->syn) {
		priv->state = TCP_SYN_SENT;
		(*ct_functions->queue_timer) (priv->timer, TCP_SYN_SENT_T);
	} else if (hdr->rst || hdr->fin) {
		priv->state = TCP_CLOSE;
		(*ct_functions->queue_timer) (priv->timer, TCP_CLOSE_T);
	} else {
		priv->state = TCP_ESTABLISHED;
		(*ct_functions->queue_timer) (priv->timer, TCP_ESTABLISHED_T);
	}

	return 1;

}

int conntrack_doublecheck_tcp(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce) {

	
	struct tcphdr* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_tcp *p;
	p = priv;
	
	if (p->sport != hdr->source || p->dport != hdr->dest) 
		return 0;

	(*ct_functions->dequeue_timer) (p->timer);
	conntrack_tcp_update_timer(priv, hdr);

	return 1;
}


void *conntrack_alloc_match_priv_tcp(void *frame, unsigned int start, struct conntrack_entry *ce) {
	
	struct tcphdr* hdr;
	hdr = frame + start;
	
	struct conntrack_priv_tcp *priv;
	priv = malloc(sizeof(struct conntrack_priv_tcp));
	priv->sport = hdr->source;
	priv->dport = hdr->dest;

	// Allocate the timer and set it up
	struct timer *t;
	t = (*ct_functions->alloc_timer) (ce);
	
	priv->timer = t;

	conntrack_tcp_update_timer(priv, hdr);

	return priv;

}

int conntrack_cleanup_match_priv_tcp(void *priv) {

	struct conntrack_priv_tcp *p = priv;

	if (p->timer) {
		(*ct_functions->dequeue_timer) (p->timer);
		(*ct_functions->cleanup_timer) (p->timer);
	}

	free(priv);
	return 1;
}
