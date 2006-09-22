
#include <netinet/ip.h>

#include "match_ipv4.h"

int match_icmp_id, match_tcp_id, match_udp_id, match_ipv6_id;

int match_register_ipv4(struct match_reg *r) {
	
	r->init = match_init_ipv4;
	r->config = match_config_ipv4;
	r->eval = match_eval_ipv4;
	r->cleanup = match_cleanup_ipv4;

	return 1;
}

int match_init_ipv4(struct match *m) {

	match_icmp_id = (*m->match_register) ("icmp");
	match_tcp_id = (*m->match_register) ("tcp");
	match_udp_id = (*m->match_register) ("udp");
	match_ipv6_id = (*m->match_register) ("ipv6");

	return 1;

}

int match_config_ipv4(struct match *m, void *params) {

	m->match_priv = params;
	return 1;

}

int match_eval_ipv4(struct match* match, void* frame, unsigned int start, unsigned int len) {
	
	struct iphdr* hdr = frame + start;
	struct in_addr saddr, daddr;
	saddr.s_addr = hdr->saddr;
	daddr.s_addr = hdr->daddr;

	ndprint("Processing IPv4 packet -> SRC : %s", inet_ntoa(saddr));
	ndprint(" | DST : %s | proto : %u" , inet_ntoa(daddr), hdr->protocol);

	if (hdr->ihl < 5)
		return 0;

	ndprint(" | IHL : %u", hdr->ihl * 4);
	match->next_start = start + (hdr->ihl * 4);
	match->next_size = ntohs(hdr->tot_len) - (hdr->ihl * 4);

	switch (hdr->protocol) {
		case IPPROTO_ICMP: // 1
			ndprint(" | ICMP packet\n");
			match->next_layer = match_icmp_id;
			break;
		case IPPROTO_TCP: // 6
			ndprint(" | TCP packet\n");
			match->next_layer = match_tcp_id;
			break;
		case IPPROTO_UDP: // 17
			ndprint(" | UDP packet\n");
			match->next_layer = match_udp_id;
			break;
		case IPPROTO_IPV6: //41
			ndprint(" | IPv6 packet\n");
			match->next_layer = match_ipv6_id;
			break;
		default:
			ndprint(" | Unhandled protocol\n");
			match->next_layer = -1;
	}
	
	if (!match->match_priv)
		return 1;

	struct match_priv_ipv4 *mp;
	mp = match->match_priv;
	
	
	if ((mp->saddr.s_addr & mp->snetmask.s_addr) != (saddr.s_addr & mp->snetmask.s_addr))
		return 0;
	if ((mp->daddr.s_addr & mp->dnetmask.s_addr) != (daddr.s_addr & mp->dnetmask.s_addr))
		return 0;
	if ((mp->proto & mp->proto_mask) != (hdr->protocol & mp->proto_mask))
		return 0;
		

	
	return 1;
}

int match_cleanup_ipv4(struct match *m) {

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
