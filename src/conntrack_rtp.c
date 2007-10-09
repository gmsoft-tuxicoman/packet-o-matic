/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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
	r->flags = CT_DIR_ONEWAY;

	ct_functions = ct_funcs;
	
	return 1;
}


uint32_t conntrack_get_hash_rtp(struct frame *f, unsigned int start, unsigned int flags) {

	struct rtphdr* hdr;
	
	hdr = f->buff + start;	

	// Compute the hash

	uint32_t rtp_hash = jhash_1word(hdr->ssrc, INITVAL);

	return rtp_hash;

}

int conntrack_doublecheck_rtp(struct frame *f, unsigned int start, void *priv, unsigned int flags) {

	

	struct rtphdr* hdr;
	hdr = f->buff + start;

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


void *conntrack_alloc_match_priv_rtp(struct frame *f, unsigned int start, struct conntrack_entry *ce) {
	
	struct rtphdr* hdr;
	hdr = f->buff + start;
	

	// Allocate the rtp priv
	struct conntrack_priv_rtp *priv;
	priv = malloc(sizeof(struct conntrack_priv_rtp));
	bzero(priv, sizeof(struct conntrack_priv_rtp));
	priv->ssrc = hdr->ssrc;
	priv->payload_type = hdr->payload_type;


	// Allocate the timeout and set it up
	struct timer *t;
	t = (*ct_functions->alloc_timer) (ce, f->input);

	priv->timer = t;

	// Put the timeout at the end of the list

	(*ct_functions->queue_timer) (t, RTP_TIMEOUT);

	return priv;

}

int conntrack_cleanup_match_priv_rtp(void *priv) {

	struct conntrack_priv_rtp *p = priv;

	if (p->timer) {
		(*ct_functions->cleanup_timer) (p->timer);
	}

	free(priv);
	return 1;
}


