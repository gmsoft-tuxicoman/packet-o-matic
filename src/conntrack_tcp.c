/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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
#include "ptype_uint16.h"


#define INITVAL 0x84fa0b2c

struct ptype *tcp_syn_sent_t, *tcp_syn_recv_t, *tcp_last_ack_t, *tcp_close_t, *tcp_time_wait_t, *tcp_established_t;


int conntrack_register_tcp(struct conntrack_reg *r) {
	
	r->get_hash = conntrack_get_hash_tcp;
	r->doublecheck = conntrack_doublecheck_tcp;
	r->alloc_match_priv = conntrack_alloc_match_priv_tcp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_tcp;
	r->unregister = conntrack_unregister_tcp;
	r->flags = CT_DIR_BOTH;

	tcp_syn_sent_t = ptype_alloc("uint16", "seconds");
	tcp_syn_recv_t = ptype_alloc("uint16", "seconds");
	tcp_last_ack_t = ptype_alloc("uint16", "seconds");
	tcp_close_t = ptype_alloc("uint16", "seconds");
	tcp_time_wait_t = ptype_alloc("uint16", "seconds");
	tcp_established_t = ptype_alloc("uint16", "seconds");

	if (!tcp_syn_sent_t || !tcp_syn_recv_t || !tcp_last_ack_t || !tcp_close_t || !tcp_time_wait_t || !tcp_established_t) {
		conntrack_unregister_tcp(r);
		return POM_ERR;
	}


	conntrack_register_param(r->type, "syn_sent_timer", "180", tcp_syn_sent_t, "SYN sent timer");
	conntrack_register_param(r->type, "syn_recv_timer", "60", tcp_syn_recv_t, "SYN received timer");
	conntrack_register_param(r->type, "last_ack_timer", "30", tcp_last_ack_t, "Last ACK timer");
	conntrack_register_param(r->type, "close_timer", "10", tcp_close_t, "Close timer");
	conntrack_register_param(r->type, "time_wait_timer", "180", tcp_time_wait_t, "Time wait timer");
	conntrack_register_param(r->type, "established_timer", "7200", tcp_established_t, "Established timer");
	
	return POM_OK;
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
			return 0;
	}

	return tcp_hash;

}

int conntrack_tcp_update_timer(struct conntrack_priv_tcp *priv, struct tcphdr *hdr) {

	if (hdr->th_flags & TH_SYN && hdr->th_flags & TH_ACK) {
	        priv->state = STATE_TCP_SYN_RECV;
		timer_dequeue(priv->timer);
	        timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_syn_recv_t));
	} else if (hdr->th_flags & TH_SYN) {
	        priv->state = STATE_TCP_SYN_SENT;
		timer_dequeue(priv->timer);
	        timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_syn_sent_t));
	} else if (hdr->th_flags & TH_RST || hdr->th_flags & TH_FIN) {
		timer_dequeue(priv->timer);
		if (hdr->th_flags & TH_ACK) {
			priv->state = STATE_TCP_TIME_WAIT;
			timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_time_wait_t));
		} else {
			priv->state = STATE_TCP_LAST_ACK;
			timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_last_ack_t));
		}
	} else if (priv->state == STATE_TCP_LAST_ACK && hdr->th_flags & TH_ACK) {
		// Connection is closed now
		priv->state = STATE_TCP_TIME_WAIT;
		timer_dequeue(priv->timer);
	        timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_time_wait_t));
	} else if (priv->state == STATE_TCP_TIME_WAIT) {
		return POM_OK;
	} else {
	        priv->state = STATE_TCP_ESTABLISHED;
		timer_dequeue(priv->timer);
	        timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_established_t));
	}

	return POM_OK;

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
				return POM_ERR;
			break;

		case CT_DIR_REV:
			if (p->sport != hdr->th_dport || p->dport != hdr->th_sport)
				return POM_ERR;
			break;

		default:
			return POM_ERR;
	}
	
	conntrack_tcp_update_timer(priv, hdr);

	return POM_OK;
}


void *conntrack_alloc_match_priv_tcp(struct frame *f, unsigned int start, struct conntrack_entry *ce) {
	
	struct tcphdr* hdr;
	hdr = f->buff + start;
	
	struct conntrack_priv_tcp *priv;
	priv = malloc(sizeof(struct conntrack_priv_tcp));
	memset(priv, 0, sizeof(struct conntrack_priv_tcp));
	priv->sport = hdr->th_sport;
	priv->dport = hdr->th_dport;

	// Allocate the timer and set it up
	struct timer *t;
	t = conntrack_timer_alloc(ce, f->input);
	
	priv->timer = t;

	if (hdr->th_flags & TH_SYN && hdr->th_flags & TH_ACK) {
	        priv->state = STATE_TCP_SYN_RECV;
	        timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_syn_recv_t));
	} else if (hdr->th_flags & TH_SYN) {
	        priv->state = STATE_TCP_SYN_SENT;
	        timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_syn_sent_t));
	} else if (hdr->th_flags & TH_RST || hdr->th_flags & TH_FIN) {
		priv->state = STATE_TCP_LAST_ACK;
		timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_close_t));
	} else {
	        priv->state = STATE_TCP_ESTABLISHED;
	        timer_queue(priv->timer, PTYPE_UINT16_GETVAL(tcp_established_t));
	}

	return priv;

}

int conntrack_cleanup_match_priv_tcp(void *priv) {

	struct conntrack_priv_tcp *p = priv;

	if (p->timer) {
		timer_cleanup(p->timer);
	}

	free(priv);
	return POM_OK;
}

int conntrack_unregister_tcp(struct conntrack_reg *r) {

	ptype_cleanup(tcp_syn_sent_t);
	ptype_cleanup(tcp_syn_recv_t);
	ptype_cleanup(tcp_last_ack_t);
	ptype_cleanup(tcp_close_t);
	ptype_cleanup(tcp_time_wait_t);
	ptype_cleanup(tcp_established_t);

	return POM_OK;
}



