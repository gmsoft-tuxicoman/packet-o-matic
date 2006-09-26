
#include "match_ethernet.h"

int match_ipv4_id, match_ipv6_id, match_arp_id;

int match_register_ethernet(struct match_reg *r) {


	r->init = match_init_ethernet;
	r->config = match_config_ethernet;
	r->eval = match_eval_ethernet;
	r->cleanup = match_cleanup_ethernet;
	
	return 1;
}

int match_init_ethernet(struct match *m) {
	
	match_ipv4_id = (*m->match_register) ("ipv4");
	match_ipv6_id = (*m->match_register) ("ipv6");
	match_arp_id = (*m->match_register) ("arp");
	return 1;

}

int match_config_ethernet(struct match *m, void *params) {

	m->match_priv = params;
	return 1;

}

int match_eval_ethernet(struct match* match, void* frame, unsigned int start, unsigned int len) {
	
	struct ethhdr *ehdr = frame + start;

	match->next_start = start + sizeof(struct ethhdr);
	match->next_size = len - sizeof(struct ethhdr);

	ndprint("Processing ethernet frame -> SMAC : ");
	ndprint_hex(ehdr->h_source, 6);
	ndprint("| DMAC : ");
	ndprint_hex(ehdr->h_dest, 6);
	ndprint("| proto : ");
	ndprint_hex((char*)&ehdr->h_proto, 2);

	switch (ntohs(ehdr->h_proto)) {
		case 0x0800:
			ndprint("| IPv4 packet\n");
			match->next_layer = match_ipv4_id;
			break;
		case 0x0806:
			ndprint("| ARP packet\n");
			match->next_layer = match_arp_id;
			break;
		case 0x86dd:
			ndprint("| IPv6 packet\n");
			match->next_layer = match_ipv6_id;
			break;
		default:
			ndprint("| Unhandled packet\n");
			match->next_layer = -1;
	}

	if (!match->match_priv)
		return 1;

	struct match_priv_ethernet *mp = match->match_priv;
	
	if (!mask_compare(mp->smac, ehdr->h_source, mp->smac_mask, 6))
		return 0;

	if (!mask_compare(mp->dmac, ehdr->h_dest, mp->dmac_mask, 6))
		return 0;

	if (!mask_compare(mp->proto, (char*)&ehdr->h_proto, mp->proto_mask, 2))
		return 0;


	return 1;
}

int match_cleanup_ethernet(struct match *m) {

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
