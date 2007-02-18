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


#include "conntrack_udp.h"
#include <netinet/udp.h>


#define INITVAL 0x7513adf4

#define UDP_TIMEOUT 180 // 180 sec of timeout for udp connections

struct conntrack_functions *ct_functions;


int conntrack_register_udp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs) {
	
	r->get_hash = conntrack_get_hash_udp;
	r->doublecheck = conntrack_doublecheck_udp;
	r->alloc_match_priv = conntrack_alloc_match_priv_udp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_udp;
	r->flags = CT_DIR_BOTH;
	
	ct_functions = ct_funcs;
	
	return 1;
}


uint32_t conntrack_get_hash_udp(void *frame, unsigned int start, unsigned int flags) {

	struct udphdr* hdr;
	
	hdr = frame + start;	

	// Compute the hash

	uint32_t udp_hash;
	switch (flags) {
		case CT_DIR_NONE:
		case CT_DIR_FWD:
			udp_hash = jhash_1word((hdr->uh_sport << 16) |  hdr->uh_dport, INITVAL);
			break;

		case CT_DIR_REV:
			udp_hash = jhash_1word((hdr->uh_dport << 16) |  hdr->uh_sport, INITVAL);
			break;

		default:
			ndprint("Error, unknown direction for conntrack\n");
			return 0;
	}

	return udp_hash;

}

int conntrack_doublecheck_udp(void *frame, unsigned int start, void *priv, unsigned int flags) {

	struct udphdr* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_udp *p;
	p = priv;
	
	switch (flags) {
		case CT_DIR_NONE:
		case CT_DIR_FWD:
			if (p->sport != hdr->uh_sport || p->dport != hdr->uh_dport)
				return 0;
			break;

		case CT_DIR_REV:
			if (p->sport != hdr->uh_dport || p->dport != hdr->uh_sport)
				return 0;
			break;
		
		default:
			ndprint("Error, unknown direction for conntrack\n");
			return 0;
	}



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
	priv->sport = hdr->uh_sport;
	priv->dport = hdr->uh_dport;


	// Allocate the timer and set it up
	struct timer *t;
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


