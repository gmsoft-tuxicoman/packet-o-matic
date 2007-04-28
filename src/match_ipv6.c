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

#define PARAMS_NUM 5

char *match_ipv6_params[PARAMS_NUM][3] = {

	{ "saddr", "::", "source ip address" },
	{ "snetmask", "0", "netmask of the source" },
	{ "daddr", "::", "destination ip address" },
	{ "dnetmask", "0", "netmask of the netmask" },
	{ "flabel", "0/0", "Flow label"}, 

};

int match_icmpv6_id, match_tcp_id, match_udp_id;
struct match_functions *m_functions;
struct layer_info *match_src_info, *match_dst_info, *match_fl_info, *match_hl_info;

int match_register_ipv6(struct match_reg *r, struct match_functions *m_funcs) {

	copy_params(r->params_name, match_ipv6_params, 0, PARAMS_NUM);
	copy_params(r->params_help, match_ipv6_params, 2, PARAMS_NUM);
	
	r->init = match_init_ipv6;
	r->reconfig = match_reconfig_ipv6;
	r->identify = match_identify_ipv6;
	r->eval = match_eval_ipv6;
	r->cleanup = match_cleanup_ipv6;
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


	return 1;
}

int match_unregister_ipv6(struct match_reg *r) {

	free(match_src_info->val.c);
	free(match_dst_info->val.c);

	return 1;
}

int match_init_ipv6(struct match *m) {

	copy_params(m->params_value, match_ipv6_params, 1, PARAMS_NUM);

	return 1;

}

int match_reconfig_ipv6(struct match *m) {

	if (!m->match_priv) {
		m->match_priv = malloc(sizeof(struct match_priv_ipv6));
		bzero(m->match_priv, sizeof(struct match_priv_ipv6));
	}
	struct match_priv_ipv6 *p = m->match_priv;

	int res=1, i;
	unsigned char mask = 0;

	res &= inet_pton(AF_INET6, m->params_value[0], &p->saddr) > 0;
	res &= sscanf(m->params_value[1], "%hhu", &mask) > 0;
	bzero(p->snetmask, 16);
	for (i = 0; i < (mask / 8); i++)
		p->snetmask[i] = 255;
	if (mask % 8)
		p->snetmask[i] = 2 << ((8 - (mask % 8)) - 1);
	
	res &= inet_pton(AF_INET6, m->params_value[2], &p->daddr) > 0;
	res &= sscanf(m->params_value[3], "%hhu", &mask) > 0;
	bzero(p->dnetmask, 16);
	for (i = 0; i < (mask / 8); i++)
		p->dnetmask[i] = 255;
	if (mask % 8)
		p->dnetmask[i] = 2 << ((8 - (mask % 8)) - 1);

	// flowlabel
	if (sscanf(m->params_value[4], "%5X/%5X", &p->flabel, &p->flabelmask) == 1)
			p->flabelmask= 0xfffff;
	else
			res &= 0;

	return res;
	
}

int match_identify_ipv6(struct layer* l, void* frame, unsigned int start, unsigned int len) {

	struct ip6_hdr* hdr = frame + start;
	unsigned int hdrlen = sizeof(struct ip6_hdr);

	memcpy(match_src_info->val.c, hdr->ip6_src.s6_addr, 16);
	memcpy(match_dst_info->val.c, hdr->ip6_dst.s6_addr, 16);

	match_fl_info->val.ui32 = ntohl(hdr->ip6_flow) & 0xfffff;
	match_hl_info->val.ui32 = hdr->ip6_hlim;

	unsigned int nhdr = hdr->ip6_nxt;
	l->payload_size = ntohs(hdr->ip6_plen);
	l->payload_start = start + hdrlen;

	while (hdrlen < len) {

		struct ip6_ext *ehdr;
		switch (nhdr) {
			case IPPROTO_HOPOPTS: // 0
			case IPPROTO_ROUTING: // 43
			case IPPROTO_FRAGMENT: // 44
			case IPPROTO_DSTOPTS: // 60
				ehdr = frame + l->payload_start;
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

int match_eval_ipv6(struct match* match, void* frame, unsigned int start, unsigned int len, struct layer *l) {
	
	struct ip6_hdr* hdr = frame + start;
	struct match_priv_ipv6 *mp;
	mp = match->match_priv;

	if (!mask_compare(mp->saddr.s6_addr, hdr->ip6_src.s6_addr, mp->snetmask, 16))
		return 0;
	
	if (!mask_compare(mp->daddr.s6_addr, hdr->ip6_dst.s6_addr, mp->dnetmask, 16))
		return 0;
	
	// flow label
	if ((mp->flabel & mp->flabelmask) != (ntohl(hdr->ip6_flow) & mp->flabelmask))
		return 0;
	
	return 1;
}

int match_cleanup_ipv6(struct match *m) {

	clean_params(m->params_value, PARAMS_NUM);

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}

int match_layer_info_snprintf_ipv6(char *buff, unsigned int len, struct layer_info *inf) {

	char addrbuff[INET6_ADDRSTRLEN + 1];
	bzero(addrbuff, INET6_ADDRSTRLEN + 1);

	inet_ntop(AF_INET6, inf->val.c, addrbuff, INET6_ADDRSTRLEN);
	strncpy(buff, addrbuff, len);

	return strlen(buff);

}
