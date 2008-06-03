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


#include "conntrack_udp.h"
#include "ptype_uint16.h"

#define __FAVOR_BSD // We use BSD favor of the udp header
#include <netinet/udp.h>


#define INITVAL 0x7513adf4

static struct ptype *udp_timeout;

int conntrack_register_udp(struct conntrack_reg *r) {
	
	r->get_hash = conntrack_get_hash_udp;
	r->doublecheck = conntrack_doublecheck_udp;
	r->alloc_match_priv = conntrack_alloc_match_priv_udp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_udp;
	r->unregister = conntrack_unregister_udp;
	r->flags = CT_DIR_BOTH;
	
	udp_timeout = ptype_alloc("uint16", "seconds");

	if (!udp_timeout)
		return POM_ERR;

	conntrack_register_param(r->type, "timeout", "180", udp_timeout, "Connection timeout");

	return POM_OK;
}


static uint32_t conntrack_get_hash_udp(struct frame *f, unsigned int start, unsigned int flags) {

	struct udphdr* hdr;
	
	hdr = f->buff + start;	

	// Compute the hash

	uint32_t udp_hash;
	switch (flags) {
		case CT_DIR_ONEWAY:
		case CT_DIR_FWD:
			udp_hash = jhash_1word((hdr->uh_sport << 16) |  hdr->uh_dport, INITVAL);
			break;

		case CT_DIR_REV:
			udp_hash = jhash_1word((hdr->uh_dport << 16) |  hdr->uh_sport, INITVAL);
			break;

		default:
			return 0;
	}

	return udp_hash;

}

static int conntrack_doublecheck_udp(struct frame *f, unsigned int start, void *priv, unsigned int flags) {

	struct udphdr* hdr;
	hdr = f->buff + start;

	// Check if there is a collision
	
	struct conntrack_priv_udp *p;
	p = priv;
	
	switch (flags) {
		case CT_DIR_ONEWAY:
		case CT_DIR_FWD:
			if (p->sport != hdr->uh_sport || p->dport != hdr->uh_dport)
				return POM_ERR;
			break;

		case CT_DIR_REV:
			if (p->sport != hdr->uh_dport || p->dport != hdr->uh_sport)
				return POM_ERR;
			break;
		
		default:
			return POM_ERR;
	}



	// Remove the timer from the queue
	timer_dequeue(p->timer);

	// And requeue it at the end
	timer_queue(p->timer, PTYPE_UINT16_GETVAL(udp_timeout));

	return POM_OK;
}


static void *conntrack_alloc_match_priv_udp(struct frame *f, unsigned int start, struct conntrack_entry *ce) {
	
	struct udphdr* hdr;
	hdr = f->buff + start;
	

	// Allocate the udp priv
	struct conntrack_priv_udp *priv;
	priv = malloc(sizeof(struct conntrack_priv_udp));
	memset(priv, 0, sizeof(struct conntrack_priv_udp));
	priv->sport = hdr->uh_sport;
	priv->dport = hdr->uh_dport;


	// Allocate the timer and set it up
	struct timer *t;
	t = conntrack_timer_alloc(ce, f->input);

	priv->timer = t;

	// Put the timeout at the end of the list
	
	timer_queue(t, PTYPE_UINT16_GETVAL(udp_timeout));

	return priv;

}

static int conntrack_cleanup_match_priv_udp(void *priv) {

	struct conntrack_priv_udp *p = priv;
	
	if (p->timer) {
		timer_cleanup(p->timer);
	}

	free(priv);
	return POM_OK;
}


static int conntrack_unregister_udp(struct conntrack_reg *r) {

	ptype_cleanup(udp_timeout);
	return POM_OK;

}

