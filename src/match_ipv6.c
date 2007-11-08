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


#include "match_ipv6.h"

#include <sys/socket.h>

#include "ptype_uint32.h"
#include "ptype_uint8.h"
#include "ptype_ipv6.h"

int match_icmpv6_id, match_tcp_id, match_udp_id;
struct match_functions *mf;

int field_saddr, field_daddr, field_flabel, field_hlim;

struct ptype *ptype_ipv6, *ptype_uint8, *ptype_uint32;

int match_register_ipv6(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_ipv6;
	r->unregister = match_unregister_ipv6;

	mf = m_funcs;

	match_icmpv6_id = (*mf->match_register) ("icmpv6");
	match_tcp_id = (*mf->match_register) ("tcp");
	match_udp_id = (*mf->match_register) ("udp");

	ptype_ipv6 = (*mf->ptype_alloc) ("ipv6", NULL);
	ptype_uint8 = (*mf->ptype_alloc) ("uint8", NULL);
	ptype_uint32 = (*mf->ptype_alloc) ("uint32", NULL);

	if (!ptype_ipv6 || !ptype_uint8 || !ptype_uint32) {
		match_unregister_ipv6(r);
		return POM_ERR;
	}

	field_saddr = (*mf->register_field) (r->type, "src", ptype_ipv6, "Source address");
	field_daddr = (*mf->register_field) (r->type, "dst", ptype_ipv6, "Destination address");
	field_flabel = (*mf->register_field) (r->type, "flabel", ptype_uint32, "Flow label");
	field_hlim = (*mf->register_field) (r->type, "hlim", ptype_uint8, "Hop limit");

	return POM_OK;
}



int match_identify_ipv6(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct ip6_hdr* hdr = f->buff + start;
	unsigned int hdrlen = sizeof(struct ip6_hdr);

	unsigned int nhdr = hdr->ip6_nxt;
	l->payload_size = ntohs(hdr->ip6_plen);
	l->payload_start = start + hdrlen;

	PTYPE_IPV6_SETADDR(l->fields[field_saddr], hdr->ip6_src);
	PTYPE_IPV6_SETADDR(l->fields[field_daddr], hdr->ip6_dst);
	PTYPE_UINT32_SETVAL(l->fields[field_flabel], ntohl(hdr->ip6_flow) & 0xfffff);
	PTYPE_UINT8_SETVAL(l->fields[field_hlim], hdr->ip6_hlim);

	while (hdrlen < len) {

		struct ip6_ext *ehdr;
		switch (nhdr) {
			case IPPROTO_HOPOPTS: // 0
			case IPPROTO_ROUTING: // 43
			case IPPROTO_FRAGMENT: // 44
			case IPPROTO_DSTOPTS: // 60
				ehdr = f->buff + l->payload_start;
				int ehlen = (ehdr->ip6e_len + 1) * 8;
				hdrlen += ehlen;
				l->payload_start += ehlen;
				l->payload_size -= ehlen;
				nhdr = ehdr->ip6e_nxt;
				break;
		
			case IPPROTO_TCP: // 6
				return match_tcp_id;

			case IPPROTO_UDP: // 17
				return match_udp_id;

			case IPPROTO_ICMPV6: // 58
				return match_icmpv6_id;

			case IPPROTO_NONE: // 59
				return -1;

			default:
				return POM_ERR;

		}
	}


	return POM_ERR;

}

int match_unregister_ipv6(struct match_reg *r) {
	
	(*mf->ptype_cleanup) (ptype_ipv6);
	(*mf->ptype_cleanup) (ptype_uint8);
	(*mf->ptype_cleanup) (ptype_uint32);

	return POM_OK;

}
