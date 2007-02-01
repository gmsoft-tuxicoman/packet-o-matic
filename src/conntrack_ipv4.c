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


#include "conntrack_ipv4.h"

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#ifdef HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif


#define INITVAL 0x5fb83a0c // Random value

int conntrack_register_ipv4(struct conntrack_reg *r, struct conntrack_functions *ct_funcs) {
	
	r->get_hash = conntrack_get_hash_ipv4;
	r->doublecheck = conntrack_doublecheck_ipv4;
	r->alloc_match_priv = conntrack_alloc_match_priv_ipv4;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_ipv4;
	r->flags = CT_DIR_BOTH;
	
	
	return 1;
}


uint32_t conntrack_get_hash_ipv4(void *frame, unsigned int start, unsigned int flags) {

	struct ip* hdr;
	
	hdr = frame + start;	

	// Compute the hash
	
	uint32_t ipv4_hash;
	
	switch (flags) {
		case CT_DIR_NONE:
		case CT_DIR_FWD:
			ipv4_hash = jhash_2words(hdr->ip_src.s_addr, hdr->ip_dst.s_addr, INITVAL);
			break;

		case CT_DIR_REV:
			ipv4_hash = jhash_2words(hdr->ip_dst.s_addr, hdr->ip_src.s_addr, INITVAL);
			break;

		default:
			ndprint("Error, unknown direction for conntrack\n");
			return 0;
	}


	return ipv4_hash;

}

int conntrack_doublecheck_ipv4(void *frame, unsigned int start, void *priv, unsigned int flags) {

	

	struct ip* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_ipv4 *p;
	p = priv;
	
	switch (flags) {
		case CT_DIR_NONE:
		case CT_DIR_FWD:
			if (p->saddr != hdr->ip_src.s_addr || p->daddr != hdr->ip_dst.s_addr)
				return 0;
			break;

		case CT_DIR_REV:
			if (p->saddr != hdr->ip_dst.s_addr || p->daddr != hdr->ip_dst.s_addr)
				return 0;
			break;

		default:
			ndprint("Error, unknown direction for conntrack\n");
			return 0;
	}

	return 1;
}


void *conntrack_alloc_match_priv_ipv4(void *frame, unsigned int start, struct conntrack_entry *ce) {
	
	struct ip* hdr;
	hdr = frame + start;
	
	struct conntrack_priv_ipv4 *priv;
	priv = malloc(sizeof(struct conntrack_priv_ipv4));
	priv->saddr = hdr->ip_src.s_addr;
	priv->daddr = hdr->ip_src.s_addr;

	return priv;

}

int conntrack_cleanup_match_priv_ipv4(void *priv) {

	free(priv);
	return 1;
}
