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


#include "conntrack_tcp.h"



#define INITVAL 0x84fa0b2c

#define TCP_SYN_SENT_T	2 * 60
#define TCP_SYN_RECV_T	60
#define TCP_LAST_ACK_T	30
#define TCP_CLOSE_T	2
#define TCP_ESTABLISHED_T 2 * 60 * 60

struct conntrack_functions *ct_functions;

int conntrack_register_tcp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs) {
	
	r->get_hash = conntrack_get_hash_tcp;
	r->doublecheck = conntrack_doublecheck_tcp;
	r->alloc_match_priv = conntrack_alloc_match_priv_tcp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_tcp;
	r->flags = CT_DIR_BOTH;

	ct_functions = ct_funcs;
	
	return 1;
}


uint32_t conntrack_get_hash_tcp(struct frame *f, unsigned int start, unsigned int flags) {

	struct tcphdr* hdr;
	
	hdr = f->buff + start;	

	// Compute the hash

	uint32_t tcp_hash;
	
	switch (flags) {
		case CT_DIR_ONEWAY:
		case CT_DIR_FWD:
			tcp_hash = jhash_1word((hdr->th_sport << 16) |  hdr->th_dport , INITVAL);
			break;

		case CT_DIR_REV:
			tcp_hash = jhash_1word((hdr->th_dport << 16) |  hdr->th_sport, INITVAL);
			break;

		default:
			ndprint("Error, unknown direction for conntrack\n");
			return 0;
	}

	return tcp_hash;

}

int conntrack_tcp_update_timer(struct conntrack_priv_tcp *priv, struct tcphdr *hdr) {

	if (hdr->th_flags & TH_SYN && hdr->th_flags & TH_ACK) {
	        priv->state = STATE_TCP_SYN_RECV;
	        (*ct_functions->queue_timer) (priv->timer, TCP_SYN_RECV_T);
	} else if (hdr->th_flags & TH_SYN) {
	        priv->state = STATE_TCP_SYN_SENT;
	        (*ct_functions->queue_timer) (priv->timer, TCP_SYN_SENT_T);
	} else if (hdr->th_flags & TH_RST || hdr->th_flags & TH_FIN) {
		priv->state = STATE_TCP_LAST_ACK;
		(*ct_functions->queue_timer) (priv->timer, TCP_CLOSE_T);
	} else if (priv->state == STATE_TCP_LAST_ACK && hdr->th_flags & TH_ACK) {
		// Connection is closed now
		priv->state = STATE_TCP_CLOSE;
	        (*ct_functions->queue_timer) (priv->timer, TCP_CLOSE_T);
	} else if (priv->state == STATE_TCP_CLOSE) {
		return 1;
	} else {
	        priv->state = STATE_TCP_ESTABLISHED;
	        (*ct_functions->queue_timer) (priv->timer, TCP_ESTABLISHED_T);
	}

	return 1;

}

int conntrack_doublecheck_tcp(struct frame *f, unsigned int start, void *priv, unsigned int flags) {

	
	struct tcphdr* hdr;
	hdr = f->buff + start;

	// Check if there is a collision
	
	struct conntrack_priv_tcp *p;
	p = priv;

	switch (flags) {
		case CT_DIR_ONEWAY:
		case CT_DIR_FWD:
			if (p->sport != hdr->th_sport || p->dport != hdr->th_dport ) 
				return 0;
			break;

		case CT_DIR_REV:
			if (p->sport != hdr->th_dport || p->dport != hdr->th_sport)
				return 0;
			break;

		default:
			ndprint("Error, unknown direction for conntrack\n");
			return 0;
	}
	
	(*ct_functions->dequeue_timer) (p->timer);
	conntrack_tcp_update_timer(priv, hdr);

	return 1;
}


void *conntrack_alloc_match_priv_tcp(struct frame *f, unsigned int start, struct conntrack_entry *ce) {
	
	struct tcphdr* hdr;
	hdr = f->buff + start;
	
	struct conntrack_priv_tcp *priv;
	priv = malloc(sizeof(struct conntrack_priv_tcp));
	bzero(priv, sizeof(struct conntrack_priv_tcp));
	priv->sport = hdr->th_sport;
	priv->dport = hdr->th_dport;

	// Allocate the timer and set it up
	struct timer *t;
	t = (*ct_functions->alloc_timer) (ce, f->input);
	
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
