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

#include "match_ipv4.h"

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "ptype_ipv4.h"

int match_icmp_id, match_tcp_id, match_udp_id, match_ipv6_id;
struct match_functions *m_functions;
struct layer_info *match_src_info, *match_dst_info, *match_tos_info, *match_ttl_info;

struct ptype *field_saddr, *field_daddr;

int match_register_ipv4(struct match_reg *r, struct match_functions *m_funcs) {
	
	r->identify = match_identify_ipv4;
	r->unregister = match_unregister_ipv4;

	m_functions = m_funcs;

	match_icmp_id = (*m_funcs->match_register) ("icmp");
	match_tcp_id = (*m_funcs->match_register) ("tcp");
	match_udp_id = (*m_funcs->match_register) ("udp");
	match_ipv6_id = (*m_funcs->match_register) ("ipv6");


	match_src_info = (*m_funcs->layer_info_register) (r->type, "src", LAYER_INFO_TYPE_UINT32);
	match_src_info->snprintf = match_layer_info_snprintf_ipv4;
	match_dst_info = (*m_funcs->layer_info_register) (r->type, "dst", LAYER_INFO_TYPE_UINT32);
	match_dst_info->snprintf = match_layer_info_snprintf_ipv4;
	match_tos_info = (*m_funcs->layer_info_register) (r->type, "tos", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_HEX);
	match_ttl_info = (*m_funcs->layer_info_register) (r->type, "ttl", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_ZERO);


	field_saddr = (*m_funcs->ptype_alloc) ("ipv4", NULL);
	field_daddr = (*m_funcs->ptype_alloc) ("ipv4", NULL);
	if (!field_saddr || !field_daddr) {
		match_unregister_ipv4(r);
		return POM_ERR;
	}
		

	(*m_funcs->register_param) (r->type, "saddr", field_saddr, "Source address");
	(*m_funcs->register_param) (r->type, "daddr", field_daddr, "Destination address");

	return POM_OK;
}


int match_identify_ipv4(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct in_addr saddr, daddr;
	struct ip* hdr = f->buff + start;
	saddr.s_addr = hdr->ip_src.s_addr;
	daddr.s_addr = hdr->ip_dst.s_addr;

	unsigned int hdr_len = hdr->ip_hl * 4;

	if (hdr->ip_hl < 5 || ntohs(hdr->ip_len) < hdr_len)
	        return -1;
	
	match_src_info->val.ui32 = saddr.s_addr;
	match_dst_info->val.ui32 = daddr.s_addr;
	match_ttl_info->val.ui32 = hdr->ip_ttl;
	match_tos_info->val.ui32 = hdr->ip_tos;

	l->payload_start = start + hdr_len;
	l->payload_size = ntohs(hdr->ip_len) - hdr_len;

	PTYPE_IPV4_SETADDR(field_saddr, hdr->ip_src);
	PTYPE_IPV4_SETADDR(field_daddr, hdr->ip_dst);

	switch (hdr->ip_p) {

		case IPPROTO_ICMP: // 1
			return match_icmp_id;
		case IPPROTO_TCP: // 6
			return match_tcp_id;
		case IPPROTO_UDP: // 17
			return match_udp_id;
		case IPPROTO_IPV6: //41
			return match_ipv6_id;
	}

	return -1;
}


int match_layer_info_snprintf_ipv4(char *buff, unsigned int len, struct layer_info *inf) {

	struct in_addr addr;
	addr.s_addr = (uint32_t) inf->val.ui32;

	strncpy(buff, inet_ntoa(addr), len);
	return strlen(buff);
}

int match_unregister_ipv4(struct match_reg *r) {

	(*m_functions->ptype_cleanup) (field_saddr);
	(*m_functions->ptype_cleanup) (field_daddr);
	return POM_OK;
}
