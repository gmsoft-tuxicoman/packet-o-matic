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

#include "match_linux_cooked.h"

int match_ipv4_id, match_ipv6_id;
struct match_functions *m_functions;
struct layer_info *match_pkt_type_info, *match_dev_type_info, *match_saddr_info;

int match_register_linux_cooked(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_linux_cooked;

	m_functions = m_funcs;
	
	match_ipv4_id = (*m_functions->match_register) ("ipv4");
	match_ipv6_id = (*m_functions->match_register) ("ipv6");

	match_pkt_type_info = (*m_funcs->layer_info_register) (r->type, "pkt_type", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_HEX);
	match_dev_type_info = (*m_funcs->layer_info_register) (r->type, "dev_type", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_HEX);
	match_saddr_info = (*m_funcs->layer_info_register) (r->type, "saddr", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_HEX);

	return POM_OK;
}

int match_identify_linux_cooked(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct cooked_hdr *chdr = f->buff + start;

	l->payload_start = start + sizeof(struct cooked_hdr);
	l->payload_size = len - sizeof(struct cooked_hdr);

	match_pkt_type_info->val.ui32 = ntohs(chdr->pkt_type);
	match_dev_type_info->val.ui32 = ntohs(chdr->dev_type);
	match_saddr_info->val.ui32 = ntohs(chdr->ll_saddr);

	switch (ntohs(chdr->ether_type)) {
		case 0x0800:
			return  match_ipv4_id;
		case 0x86dd:
			return match_ipv6_id;
	}

	return -1;
}

