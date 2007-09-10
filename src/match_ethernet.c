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

int match_ipv4_id, match_ipv6_id, match_arp_id;
struct match_functions *m_functions;
struct layer_info *match_src_info, *match_dst_info;

struct ptype *field_saddr, *field_daddr;

int match_register_ethernet(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_ethernet;
	r->unregister = match_unregister_ethernet;
	
	m_functions = m_funcs;
	
	match_ipv4_id = (*m_functions->match_register) ("ipv4");
	match_ipv6_id = (*m_functions->match_register) ("ipv6");
	match_arp_id = (*m_functions->match_register) ("arp");

	match_src_info = (*m_funcs->layer_info_register) (r->type, "src", LAYER_INFO_TYPE_CUSTOM);
	match_src_info->snprintf = match_layer_info_snprintf_ethernet;
	match_src_info->val.c = malloc(6);
	match_dst_info = (*m_funcs->layer_info_register) (r->type, "dst", LAYER_INFO_TYPE_CUSTOM);
	match_dst_info->snprintf = match_layer_info_snprintf_ethernet;
	match_dst_info->val.c = malloc(6);


	field_saddr = (*m_funcs->ptype_alloc) ("mac", NULL);
	field_daddr = (*m_funcs->ptype_alloc) ("mac", NULL);
	if (!field_saddr || !field_daddr) {
		match_unregister_ethernet(r);
		return POM_ERR;
	}
		

	(*m_funcs->register_param) (r->type, "saddr", field_saddr, "Source MAC address");
	(*m_funcs->register_param) (r->type, "daddr", field_daddr, "Destination MAC address");

	return POM_OK;

}

int match_identify_ethernet(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct ether_header *ehdr = f->buff + start;

	l->payload_start = start + sizeof(struct ether_header);
	l->payload_size = len - sizeof(struct ether_header);


	memcpy(match_src_info->val.c, ehdr->ether_shost, 6);
	memcpy(match_dst_info->val.c, ehdr->ether_dhost, 6);
	

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

int match_layer_info_snprintf_ethernet(char *buff, unsigned int len, struct layer_info *inf) {

	return snprintf(buff, len - 1, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
		inf->val.c[0],
		inf->val.c[1],
		inf->val.c[2],
		inf->val.c[3],
		inf->val.c[4],
		inf->val.c[5]);

}

int match_unregister_ethernet(struct match_reg *r) {

	(m_functions->ptype_cleanup) (field_saddr);
	(m_functions->ptype_cleanup) (field_daddr);
	free(match_src_info->val.c);
	free(match_dst_info->val.c);
	return POM_OK;
}

