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

#include "match_ipv4.h"

#include "ptype_ipv4.h"
#include "ptype_uint8.h"

#define __USE_BSD 1 // We use BSD favor of the ip header
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

static struct match_dep *match_undefined, *match_icmp, *match_tcp, *match_udp, *match_ipv6, *match_gre;

static int field_saddr, field_daddr, field_tos, field_ttl;

static struct ptype *ptype_ipv4, *ptype_uint8, *ptype_uint8_hex;

int match_register_ipv4(struct match_reg *r) {
	
	r->identify = match_identify_ipv4;
	r->get_expectation = match_get_expectation_ipv4;
	r->unregister = match_unregister_ipv4;

	match_undefined = match_add_dependency(r->type, "undefined");
	match_icmp = match_add_dependency(r->type, "icmp");
	match_tcp = match_add_dependency(r->type, "tcp");
	match_udp = match_add_dependency(r->type, "udp");
	match_ipv6 = match_add_dependency(r->type, "ipv6");
	match_gre = match_add_dependency(r->type, "gre");

	ptype_ipv4 = ptype_alloc("ipv4", NULL);
	ptype_uint8 = ptype_alloc("uint8", NULL);
	ptype_uint8_hex = ptype_alloc("uint8", NULL);
	ptype_uint8_hex->print_mode = PTYPE_UINT8_PRINT_HEX;

	if (!ptype_ipv4 || !ptype_uint8 || !ptype_uint8_hex) {
		match_unregister_ipv4(r);
		return POM_ERR;
	}

	field_saddr = match_register_field(r->type, "src", ptype_ipv4, "Source address");
	field_daddr = match_register_field(r->type, "dst", ptype_ipv4, "Destination address");
	field_tos = match_register_field(r->type, "tos", ptype_uint8_hex, "Type of service");
	field_ttl = match_register_field(r->type, "ttl", ptype_uint8, "Time to live");

	return POM_OK;
}


int match_identify_ipv4(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct in_addr saddr, daddr;
	struct ip* hdr = f->buff + start;
	saddr.s_addr = hdr->ip_src.s_addr;
	daddr.s_addr = hdr->ip_dst.s_addr;

	unsigned int hdr_len = hdr->ip_hl * 4;

	if (len < sizeof(struct ip) || // lenght smaller than header
		hdr->ip_hl < 5 || // ip header < 5 bytes
		ntohs(hdr->ip_len) < hdr_len || // datagram size < ip header length
		ntohs(hdr->ip_len) > len) // datagram size > given size
	        return POM_ERR;

	l->payload_start = start + hdr_len;
	l->payload_size = ntohs(hdr->ip_len) - hdr_len;


	PTYPE_IPV4_SETADDR(l->fields[field_saddr], hdr->ip_src);
	PTYPE_IPV4_SETADDR(l->fields[field_daddr], hdr->ip_dst);
	PTYPE_UINT8_SETVAL(l->fields[field_tos], hdr->ip_tos);
	PTYPE_UINT8_SETVAL(l->fields[field_ttl], hdr->ip_ttl);
		

	switch (hdr->ip_p) {

		case IPPROTO_ICMP: // 1
			return match_icmp->id;
		case IPPROTO_TCP: // 6
			return match_tcp->id;
		case IPPROTO_UDP: // 17
			return match_udp->id;
		case IPPROTO_IPV6: //41
			return match_ipv6->id;
		case IPPROTO_GRE: // 47
			return match_gre->id;
	}

	return match_undefined->id;
}

static int match_get_expectation_ipv4(int field_id, int direction) {

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

static int match_unregister_ipv4(struct match_reg *r) {

	ptype_cleanup(ptype_ipv4);
	ptype_cleanup(ptype_uint8);
	ptype_cleanup(ptype_uint8_hex);

	return POM_OK;
}
