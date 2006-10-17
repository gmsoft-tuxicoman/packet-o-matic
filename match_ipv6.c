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


#include <netinet/ip6.h>

#include "match_ipv6.h"

#define PARAMS_NUM 4

char *match_ipv6_params[PARAMS_NUM][3] = {

	{ "saddr", "::", "source ip address" },
	{ "snetmask", "::", "netmask of the source" },
	{ "daddr", "::", "destination ip address" },
	{ "dnetmask", "::", "netmask of the netmask" },

};

int match_icmpv6_id, match_tcp_id, match_udp_id;

int match_register_ipv6(struct match_reg *r) {

	copy_params(r->params_name, match_ipv6_params, 0, PARAMS_NUM);
	copy_params(r->params_help, match_ipv6_params, 2, PARAMS_NUM);
	
	r->init = match_init_ipv6;
	r->reconfig = match_reconfig_ipv6;
	r->eval = match_eval_ipv6;
	r->cleanup = match_cleanup_ipv6;

	return 1;
}

int match_init_ipv6(struct match *m) {

	copy_params(m->params_value, match_ipv6_params, 1, PARAMS_NUM);

	match_icmpv6_id = (*m->match_register) ("icmpv6");
	match_tcp_id = (*m->match_register) ("tcp");
	match_udp_id = (*m->match_register) ("udp");

	return 1;

}

int match_reconfig_ipv6(struct match *m) {


	if (!m->match_priv) {
		m->match_priv = malloc(sizeof(struct match_priv_ipv6));
		bzero(m->match_priv, sizeof(struct match_priv_ipv6));
	}
	struct match_priv_ipv6 *p = m->match_priv;

	int res = 1;
	res &= inet_pton(AF_INET6, m->params_value[0], &p->saddr) > 0;
	res &= sscanf(m->params_value[1], "%c", &p->snetmask) > 0;
	res &= inet_pton(AF_INET6, m->params_value[0], &p->daddr) > 0;
	res &= sscanf(m->params_value[3], "%c", &p->dnetmask) > 0;


	return res;

}

int match_eval_ipv6(struct match* match, void* frame, unsigned int start, unsigned int len) {
	
	struct ip6_hdr* hdr = frame + start;

#ifdef NDEBUG	

	char addrbuff[INET6_ADDRSTRLEN + 1];
	bzero(addrbuff, INET6_ADDRSTRLEN + 1);
	inet_ntop(AF_INET6, &hdr->ip6_src.s6_addr, addrbuff, INET6_ADDRSTRLEN);
	ndprint("Processing IPv6 packet -> SRC : %s", addrbuff);
	bzero(addrbuff, INET6_ADDRSTRLEN + 1);
	inet_ntop(AF_INET6, &hdr->ip6_dst.s6_addr, addrbuff, INET6_ADDRSTRLEN);
	ndprint(" | DST : %s" , addrbuff);


#endif

	unsigned int nhdr = hdr->ip6_nxt;
	match->next_size = ntohs(hdr->ip6_plen);

	match->next_start = start +  sizeof(struct ip6_hdr);
	while (match->next_start + 1 < len) {

		struct ip6_ext *ehdr;
		ndprint(" | NHDR : %u", nhdr);
		switch (nhdr) {
			case IPPROTO_HOPOPTS: // 0
			case IPPROTO_ROUTING: // 43
			case IPPROTO_FRAGMENT: // 44
			case IPPROTO_DSTOPTS: // 60
				ehdr = frame + match->next_start;
				int hlen = (ehdr->ip6e_len + 1) * 8;
				match->next_start += hlen;
				match->next_size -= hlen;
				nhdr = ehdr->ip6e_nxt;
				break;
		
			case IPPROTO_TCP: // 6
				ndprint(" | TCP packet");
				match->next_layer = match_tcp_id;
				break;
			case IPPROTO_UDP: // 17
				ndprint(" | UDP packet");
				match->next_layer = match_udp_id;
				break;

			case IPPROTO_ICMPV6: // 58
				ndprint(" | ICMPv6 packet");
				match->next_layer = match_icmpv6_id;
				break;

			case IPPROTO_NONE: // 59
				ndprint(" | Unknown packet");
				match->next_layer = -1;

			default:
				ndprint(" | Unhandled protocol");
				match->next_layer = -1;
				break;

		}
		if (match->next_layer)
			break;
	}

	ndprint(" | SIZE : %u\n", match->next_size);

	if (!match->match_priv)
		return 1;

	struct match_priv_ipv6 *mp;
	mp = match->match_priv;

	char mask[16];
	int i;

	bzero(mask, 16);
	for (i = 0; i < mp->snetmask; i++)
		mask[i / 8] += (1 << (i % 8));

	for (i = 0; i < 16; i++)
		dprint("%X", mask[i]);
	dprint("\n");


	if (!mask_compare(mp->saddr.s6_addr, hdr->ip6_src.s6_addr, mask, 16))
		return 0;

	bzero(mask, 16);
	for (i = 0; i < mp->dnetmask; i++)
		mask[i / 8] += (1 << (i % 8));

	for (i = 0; i < 16; i++)
		dprint("%X", mask[i]);
	dprint("\n");
	
	if (!mask_compare(mp->daddr.s6_addr, hdr->ip6_dst.s6_addr, mask, 16))
		return 0;
	return 1;
}

int match_cleanup_ipv6(struct match *m) {

	clean_params(m->params_value, PARAMS_NUM);

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
