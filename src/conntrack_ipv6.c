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


#include "conntrack_ipv6.h"

#define INITVAL 0x8529fc6a // Random value

int conntrack_register_ipv6(struct conntrack_reg *r, struct conntrack_functions *ct_funcs) {
	
	r->get_hash = conntrack_get_hash_ipv6;
	r->doublecheck = conntrack_doublecheck_ipv6;
	r->alloc_match_priv = conntrack_alloc_match_priv_ipv6;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_ipv6;
	r->flags = CT_DIR_BOTH;
	
	
	return 1;
}


uint32_t conntrack_get_hash_ipv6(struct frame *f, unsigned int start, unsigned int flags) {

	struct ip6_hdr* hdr;
	
	hdr = f->buff + start;	

	// Compute the hash


	char addrs[32];
	
	switch (flags) {
		case CT_DIR_ONEWAY:
		case CT_DIR_FWD:
			memcpy(addrs, hdr->ip6_src.s6_addr, 16);
			memcpy(addrs + 16, hdr->ip6_dst.s6_addr, 16);
			break;

		case CT_DIR_REV:
			memcpy(addrs, hdr->ip6_dst.s6_addr, 16);
			memcpy(addrs + 16, hdr->ip6_src.s6_addr, 16);
			break;

		default:
			return 0;
	}


	uint32_t ipv6_hash = jhash(addrs, 32, INITVAL);

	return ipv6_hash;

}

int conntrack_doublecheck_ipv6(struct frame *f, unsigned int start, void *priv, unsigned int flags) {

	

	struct ip6_hdr* hdr;
	hdr = f->buff + start;

	// Check if there is a collision
	
	struct conntrack_priv_ipv6 *p;
	p = priv;
	
	int i;

	switch (flags) {

		case CT_DIR_ONEWAY:
		case CT_DIR_FWD:
			for (i = 0; i < 16; i++)
				if (hdr->ip6_src.s6_addr[i] != p->saddr.s6_addr[i] || hdr->ip6_dst.s6_addr[i] != p->daddr.s6_addr[i])
					return 0;
			break;

		case CT_DIR_REV:
			for (i = 0; i < 16; i++)
				if (hdr->ip6_src.s6_addr[i] != p->daddr.s6_addr[i] || hdr->ip6_dst.s6_addr[i] != p->saddr.s6_addr[i])
					return 0;
			break;
		default:
			return 0;

	}

	return 1;
}


void *conntrack_alloc_match_priv_ipv6(struct frame *f, unsigned int start, struct conntrack_entry *ce) {
	
	struct ip6_hdr* hdr;
	hdr = f->buff + start;
	
	struct conntrack_priv_ipv6 *priv;
	priv = malloc(sizeof(struct conntrack_priv_ipv6));
	memcpy(priv->saddr.s6_addr, hdr->ip6_src.s6_addr, 16);
	memcpy(priv->daddr.s6_addr, hdr->ip6_dst.s6_addr, 16);

	return priv;

}

int conntrack_cleanup_match_priv_ipv6(void *priv) {

	free(priv);
	return 1;
}
