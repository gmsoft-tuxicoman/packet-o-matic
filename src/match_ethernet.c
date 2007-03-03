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


#include "match_ethernet.h"

#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>

#ifdef HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif

#define PARAMS_NUM 4

char *match_ethernet_params[PARAMS_NUM][3] = {

	{ "smac", "00:00:00:00:00:00", "source mac address"},
	{ "smac_mask", "00:00:00:00:00:00", "source mac mask"},
	{ "dmac", "00:00:00:00:00:00", "destination mac address"},
	{ "dmac_mask", "00:00:00:00:00:00", "destination mac mask"},

};

int match_ipv4_id, match_ipv6_id, match_arp_id;
struct match_functions *m_functions;
struct layer_info *match_src_info, *match_dst_info;


int match_register_ethernet(struct match_reg *r, struct match_functions *m_funcs) {

	copy_params(r->params_name, match_ethernet_params, 0, PARAMS_NUM);
	copy_params(r->params_help, match_ethernet_params, 2, PARAMS_NUM);


	r->init = match_init_ethernet;
	r->reconfig = match_reconfig_ethernet;
	r->identify = match_identify_ethernet;
	r->eval = match_eval_ethernet;
	r->cleanup = match_cleanup_ethernet;
	
	m_functions = m_funcs;
	
	match_ipv4_id = (*m_functions->match_register) ("ipv4");
	match_ipv6_id = (*m_functions->match_register) ("ipv6");
	match_arp_id = (*m_functions->match_register) ("arp");

	match_src_info = (*m_funcs->layer_info_register) (r->match_type, "src", LAYER_INFO_STRING);
	match_dst_info = (*m_funcs->layer_info_register) (r->match_type, "dst", LAYER_INFO_STRING);

	return 1;
}

int match_init_ethernet(struct match *m) {

	copy_params(m->params_value, match_ethernet_params, 1, PARAMS_NUM);
	return 1;

}


int match_reconfig_ethernet(struct match *m) {

	if (!m->match_priv) {
		m->match_priv = malloc(sizeof(struct match_priv_ethernet));
		bzero(m->match_priv, sizeof(struct match_priv_ethernet));
	}

	struct match_priv_ethernet *p = m->match_priv;
	int res = 0;
	res += sscanf(m->params_value[0], "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", p->smac, p->smac + 1, p->smac + 2, p->smac + 3, p->smac + 4, p->smac + 5);
	res += sscanf(m->params_value[1], "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", p->smac_mask, p->smac_mask + 1, p->smac_mask + 2, p->smac_mask + 3, p->smac_mask + 4, p->smac_mask + 5);
	res += sscanf(m->params_value[2], "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", p->dmac, p->dmac + 1, p->dmac + 2, p->dmac + 3, p->dmac + 4, p->dmac + 5);
	res += sscanf(m->params_value[3], "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", p->dmac_mask, p->dmac_mask + 1, p->dmac_mask + 2, p->dmac_mask + 3, p->dmac_mask + 4, p->dmac_mask + 5);

	return (res == (4 * 6));

}

int match_identify_ethernet(struct layer* l, void* frame, unsigned int start, unsigned int len) {

	struct ether_header *ehdr = frame + start;

	l->payload_start = start + sizeof(struct ether_header);
	l->payload_size = len - sizeof(struct ether_header);

	
	char addrbuff[18];
	bzero(addrbuff, 18);
	sprintf(addrbuff, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", ehdr->ether_shost[0], ehdr->ether_shost[1], ehdr->ether_shost[2], ehdr->ether_shost[3], ehdr->ether_shost[4], ehdr->ether_shost[5]);
	(*m_functions->layer_info_set_str) (match_src_info, addrbuff);
	sprintf(addrbuff, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", ehdr->ether_dhost[0], ehdr->ether_dhost[1], ehdr->ether_dhost[2], ehdr->ether_dhost[3], ehdr->ether_dhost[4], ehdr->ether_dhost[5]);
	(*m_functions->layer_info_set_str) (match_dst_info, addrbuff);

	switch (ntohs(ehdr->ether_type)) {
		case 0x0800:
			return  match_ipv4_id;
		case 0x0806:
			return match_arp_id;
		case 0x86dd:
			return match_ipv6_id;
	}

	return -1;
}

int match_eval_ethernet(struct match* match, void* frame, unsigned int start, unsigned int len, struct layer *l) {
	
	struct ether_header *ehdr = frame + start;

	struct match_priv_ethernet *mp = match->match_priv;
	
	if (!mask_compare(mp->smac, ehdr->ether_shost, mp->smac_mask, 6))
		return 0;

	if (!mask_compare(mp->dmac, ehdr->ether_dhost, mp->dmac_mask, 6))
		return 0;

	if (!mask_compare(mp->proto, (unsigned char*)&ehdr->ether_type, mp->proto_mask, 2))
		return 0;


	return 1;
}

int match_cleanup_ethernet(struct match *m) {


	clean_params(m->params_value, PARAMS_NUM);

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
