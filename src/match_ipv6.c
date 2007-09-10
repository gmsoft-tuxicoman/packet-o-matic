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
#include "ptype_ipv6.h"

int match_icmpv6_id, match_tcp_id, match_udp_id;
struct match_functions *m_functions;
struct layer_info *match_src_info, *match_dst_info, *match_fl_info, *match_hl_info;

struct ptype *field_saddr, *field_daddr, *field_flabel;

int match_register_ipv6(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_ipv6;
	r->unregister = match_unregister_ipv6;

	m_functions = m_funcs;

	match_icmpv6_id = (*m_funcs->match_register) ("icmpv6");
	match_tcp_id = (*m_funcs->match_register) ("tcp");
	match_udp_id = (*m_funcs->match_register) ("udp");

	match_src_info = (*m_funcs->layer_info_register) (r->type, "src", LAYER_INFO_TYPE_CUSTOM);
	match_src_info->val.c = malloc(16);
	match_src_info->snprintf = match_layer_info_snprintf_ipv6;
	match_dst_info = (*m_funcs->layer_info_register) (r->type, "dst", LAYER_INFO_TYPE_CUSTOM);
	match_dst_info->val.c = malloc(16);
	match_dst_info->snprintf = match_layer_info_snprintf_ipv6;
	match_fl_info = (*m_funcs->layer_info_register) (r->type, "flabel", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_HEX);
	match_hl_info = (*m_funcs->layer_info_register) (r->type, "hlim", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_ZERO);


	field_saddr = (*m_funcs->ptype_alloc) ("ipv6", NULL);
	field_daddr = (*m_funcs->ptype_alloc) ("ipv6", NULL);
	field_flabel = (*m_funcs->ptype_alloc) ("uint32", NULL);
	if (!field_saddr || !field_daddr || !field_flabel) {
		match_unregister_ipv6(r);
		return POM_ERR;
	}

	(*m_funcs->register_param) (r->type, "saddr", field_saddr, "Source address");
	(*m_funcs->register_param) (r->type, "daddr", field_daddr, "Destination address");
	(*m_funcs->register_param) (r->type, "flabel", field_daddr, "Flow label");

	return POM_OK;
}



int match_identify_ipv6(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct ip6_hdr* hdr = f->buff + start;
	unsigned int hdrlen = sizeof(struct ip6_hdr);

	memcpy(match_src_info->val.c, hdr->ip6_src.s6_addr, 16);
	memcpy(match_dst_info->val.c, hdr->ip6_dst.s6_addr, 16);

	match_fl_info->val.ui32 = ntohl(hdr->ip6_flow) & 0xfffff;
	match_hl_info->val.ui32 = hdr->ip6_hlim;

	unsigned int nhdr = hdr->ip6_nxt;
	l->payload_size = ntohs(hdr->ip6_plen);
	l->payload_start = start + hdrlen;

	PTYPE_IPV6_SETADDR(field_saddr, hdr->ip6_src);
	PTYPE_IPV6_SETADDR(field_daddr, hdr->ip6_dst);
	PTYPE_UINT32_SETVAL(field_flabel, ntohl(hdr->ip6_flow) & 0xfffff);

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
				return -1;

		}
	}


	return -1;

}

int match_unregister_ipv6(struct match_reg *r) {

	free(match_src_info->val.c);
	free(match_dst_info->val.c);

	(*m_functions->ptype_cleanup) (field_saddr);
	(*m_functions->ptype_cleanup) (field_daddr);
	(*m_functions->ptype_cleanup) (field_flabel);

	return POM_OK;
}

int match_layer_info_snprintf_ipv6(char *buff, unsigned int len, struct layer_info *inf) {

	char addrbuff[INET6_ADDRSTRLEN + 1];
	bzero(addrbuff, INET6_ADDRSTRLEN + 1);

	inet_ntop(AF_INET6, inf->val.c, addrbuff, INET6_ADDRSTRLEN);
	strncpy(buff, addrbuff, len);

	return strlen(buff);

}
