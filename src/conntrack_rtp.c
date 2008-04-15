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


#include "match_rtp.h"
#include "conntrack_rtp.h"
#include "ptype_uint16.h"

#define INITVAL 0x83f0e1b6

struct ptype *rtp_timeout;

int conntrack_register_rtp(struct conntrack_reg *r) {
	
	r->get_hash = conntrack_get_hash_rtp;
	r->doublecheck = conntrack_doublecheck_rtp;
	r->alloc_match_priv = conntrack_alloc_match_priv_rtp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_rtp;
	r->unregister = conntrack_unregister_rtp;
	r->flags = CT_DIR_ONEWAY;

	rtp_timeout = ptype_alloc("uint16", "seconds");
	if (!rtp_timeout)
		return POM_ERR;

	conntrack_register_param(r->type, "timeout", "10", rtp_timeout, "Connection timeout");
	
	return POM_OK;
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
		return POM_ERR;

	// Remove the timer from the queue
	timer_dequeue(p->timer);

	// And requeue it at the end
	timer_queue(p->timer, PTYPE_UINT16_GETVAL(rtp_timeout));


	return POM_OK;
}


void *conntrack_alloc_match_priv_rtp(struct frame *f, unsigned int start, struct conntrack_entry *ce) {
	
	struct rtphdr* hdr;
	hdr = f->buff + start;
	

	// Allocate the rtp priv
	struct conntrack_priv_rtp *priv;
	priv = malloc(sizeof(struct conntrack_priv_rtp));
	memset(priv, 0, sizeof(struct conntrack_priv_rtp));
	priv->ssrc = hdr->ssrc;
	priv->payload_type = hdr->payload_type;


	// Allocate the timeout and set it up
	struct timer *t;
	t = conntrack_timer_alloc(ce, f->input);

	priv->timer = t;

	// Put the timeout at the end of the list

	timer_queue(t, PTYPE_UINT16_GETVAL(rtp_timeout));

	return priv;

}

int conntrack_cleanup_match_priv_rtp(void *priv) {

	struct conntrack_priv_rtp *p = priv;

	if (p->timer) {
		timer_cleanup(p->timer);
	}

	free(priv);
	return POM_OK;
}

int conntrack_unregister_rtp(struct conntrack_reg *r) {

	ptype_cleanup(rtp_timeout);
	return POM_OK;
}
