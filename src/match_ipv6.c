/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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

static struct match_dep *match_undefined, *match_icmpv6, *match_tcp, *match_udp;

static int field_saddr, field_daddr, field_flabel, field_hlim;

static struct ptype *ptype_ipv6, *ptype_uint8, *ptype_uint32;

int match_register_ipv6(struct match_reg *r) {

	r->identify = match_identify_ipv6;
	r->get_expectation = match_get_expectation_ipv6;
	r->unregister = match_unregister_ipv6;

	match_undefined = match_add_dependency(r->type, "undefined");
	match_icmpv6 = match_add_dependency(r->type, "icmpv6");
	match_tcp = match_add_dependency(r->type, "tcp");
	match_udp = match_add_dependency(r->type, "udp");

	ptype_ipv6 = ptype_alloc("ipv6", NULL);
	ptype_uint8 = ptype_alloc("uint8", NULL);
	ptype_uint32 = ptype_alloc("uint32", NULL);
	ptype_uint32->print_mode = PTYPE_UINT32_PRINT_HEX;

	if (!ptype_ipv6 || !ptype_uint8 || !ptype_uint32) {
		match_unregister_ipv6(r);
		return POM_ERR;
	}

	field_saddr = match_register_field(r->type, "src", ptype_ipv6, "Source address");
	field_daddr = match_register_field(r->type, "dst", ptype_ipv6, "Destination address");
	field_flabel = match_register_field(r->type, "flabel", ptype_uint32, "Flow label");
	field_hlim = match_register_field(r->type, "hlim", ptype_uint8, "Hop limit");

	return POM_OK;
}



static int match_identify_ipv6(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {


	if (len < sizeof(struct ip6_hdr))
		return POM_ERR;
	
	struct ip6_hdr* hdr = f->buff + start;
	unsigned int hdrlen = sizeof(struct ip6_hdr);

	if (hdrlen + ntohs(hdr->ip6_plen) > len)
		return POM_ERR;

	unsigned int nhdr = hdr->ip6_nxt;
	l->payload_size = ntohs(hdr->ip6_plen);
	l->payload_start = start + hdrlen;

	PTYPE_IPV6_SETADDR(l->fields[field_saddr], hdr->ip6_src);
	PTYPE_IPV6_SETADDR(l->fields[field_daddr], hdr->ip6_dst);
	PTYPE_UINT32_SETVAL(l->fields[field_flabel], ntohl(hdr->ip6_flow) & 0xfffff);
	PTYPE_UINT8_SETVAL(l->fields[field_hlim], hdr->ip6_hlim);

	while (hdrlen < len) {

		struct ip6_ehdr *ehdr;
		switch (nhdr) {
			case IPPROTO_HOPOPTS: // 0
			case IPPROTO_ROUTING: // 43
			case IPPROTO_DSTOPTS: // 60
				ehdr = f->buff + l->payload_start;
				int ehlen = (ehdr->ip6e_len + 1) * 8;
				if (ehlen > l->payload_size)
					return POM_ERR;
				hdrlen += ehlen;
				l->payload_start += ehlen;
				l->payload_size -= ehlen;
				nhdr = ehdr->ip6e_nxt;
				break;
		
			case IPPROTO_TCP: // 6
				return match_tcp->id;

			case IPPROTO_UDP: // 17
				return match_udp->id;

			case IPPROTO_ICMPV6: // 58
				return match_icmpv6->id;

			case IPPROTO_NONE: // 59
			case IPPROTO_FRAGMENT: // 44
				return match_undefined->id;

			default:
				return match_undefined->id;

		}
	}


	return match_undefined->id;

}

static int match_get_expectation_ipv6(int field_id, int direction) {

	if (field_id == field_saddr) {
		if (direction == EXPT_DIR_FWD) {
			return field_saddr;
		} else {
			return field_daddr;
		}
	} else if (field_id == field_daddr) {
		if (direction == EXPT_DIR_FWD) {
			return field_daddr;
		} else {
			return field_saddr;
		}

	}
	return POM_ERR;

}

static int match_unregister_ipv6(struct match_reg *r) {
	
	ptype_cleanup(ptype_ipv6);
	ptype_cleanup(ptype_uint8);
	ptype_cleanup(ptype_uint32);

	return POM_OK;

}
