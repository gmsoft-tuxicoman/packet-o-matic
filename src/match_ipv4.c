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

#define PARAMS_NUM 4

char *match_ipv4_params[PARAMS_NUM][3] = {

	{ "saddr", "0.0.0.0", "source ip address" },
	{ "snetmask", "0.0.0.0", "netmask of the source" },
	{ "daddr", "0.0.0.0", "destination ip address" },
	{ "dnetmask", "0.0.0.0", "netmask of the netmask" },

};

int match_icmp_id, match_tcp_id, match_udp_id, match_ipv6_id;

int match_register_ipv4(struct match_reg *r) {
	
	copy_params(r->params_name, match_ipv4_params, 0, PARAMS_NUM);
	copy_params(r->params_help, match_ipv4_params, 2, PARAMS_NUM);
	
	r->init = match_init_ipv4;
	r->reconfig = match_reconfig_ipv4;
	r->identify = match_identify_ipv4;
	r->eval = match_eval_ipv4;
	r->cleanup = match_cleanup_ipv4;

	return 1;
}

int match_init_ipv4(struct match *m) {

	copy_params(m->params_value, match_ipv4_params, 1, PARAMS_NUM);

	match_icmp_id = (*m->match_register) ("icmp");
	match_tcp_id = (*m->match_register) ("tcp");
	match_udp_id = (*m->match_register) ("udp");
	match_ipv6_id = (*m->match_register) ("ipv6");

	return 1;

}

int match_reconfig_ipv4(struct match *m) {


	if (!m->match_priv) {
		m->match_priv = malloc(sizeof(struct match_priv_ipv4));
		bzero(m->match_priv, sizeof(struct match_priv_ipv4));
	}

	struct match_priv_ipv4 *p = m->match_priv;

	int res = 1;
	res &= inet_aton(m->params_value[0], &p->saddr);
	res &= inet_aton(m->params_value[1], &p->snetmask);
	res &= inet_aton(m->params_value[2], &p->daddr);
	res &= inet_aton(m->params_value[3], &p->dnetmask);


	return res;

}

int match_identify_ipv4(struct layer* l, void* frame, unsigned int start, unsigned int len) {

	struct in_addr saddr, daddr;
	struct ip* hdr = frame + start;
	saddr.s_addr = hdr->ip_src.s_addr;
	daddr.s_addr = hdr->ip_dst.s_addr;
	ndprint("Processing IPv4 packet -> SRC : %s", inet_ntoa(saddr));
	ndprint(" | DST : %s | proto : %u" , inet_ntoa(daddr), hdr->ip_p);

	unsigned int hdr_len = hdr->ip_hl * 4;

	if (hdr->ip_hl < 5 || ntohs(hdr->ip_len) < hdr_len)
	        return -1;

	ndprint(" | IHL : %u", hdr_len);
	l->payload_start = start + hdr_len;
	l->payload_size = ntohs(hdr->ip_len) - hdr_len;
	ndprint(" | SIZE : %u", l->payload_size);

	switch (hdr->ip_p) {

		case IPPROTO_ICMP: // 1
			ndprint(" | ICMP packet\n");
			return match_icmp_id;
			break;
		case IPPROTO_TCP: // 6
			ndprint(" | TCP packet\n");
			return match_tcp_id;
			break;
		case IPPROTO_UDP: // 17
			ndprint(" | UDP packet\n");
			return match_udp_id;
			break;
		case IPPROTO_IPV6: //41
			ndprint(" | IPv6 packet\n");
			return match_ipv6_id;
			break;
		default:
			ndprint(" | Unhandled protocol\n");
	}

	return -1;
}

int match_eval_ipv4(struct match* match, void* frame, unsigned int start, unsigned int len, struct layer *l) {
	
	struct in_addr saddr, daddr;
	struct ip* hdr = frame + start; 
	saddr.s_addr = hdr->ip_src.s_addr;
	daddr.s_addr = hdr->ip_dst.s_addr;

	struct match_priv_ipv4 *mp;
	mp = match->match_priv;
	
	if ((mp->saddr.s_addr & mp->snetmask.s_addr) != (saddr.s_addr & mp->snetmask.s_addr))
		return 0;
	if ((mp->daddr.s_addr & mp->dnetmask.s_addr) != (daddr.s_addr & mp->dnetmask.s_addr))
		return 0;
	
	return 1;
}

int match_cleanup_ipv4(struct match *m) {

	clean_params(m->params_value, PARAMS_NUM);

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
