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

#include <netinet/icmp6.h>

#include "match_icmpv6.h"

int match_ipv4_id, match_ipv6_id;
struct match_functions *m_functions;
struct layer_info *match_type_info, *match_code_info;

int match_register_icmpv6(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_icmpv6;

	m_functions = m_funcs;
	
	match_ipv6_id = (*m_functions->match_register) ("ipv6");

	match_type_info = (*m_funcs->layer_info_register) (r->match_type, "type", LAYER_INFO_TYPE_UINT32);
	match_type_info->snprintf = match_layer_info_snprintf_icmpv6;
	match_code_info = (*m_funcs->layer_info_register) (r->match_type, "code", LAYER_INFO_TYPE_UINT32);

	return 1;
}

int match_identify_icmpv6(struct layer* l, void* frame, unsigned int start, unsigned int len) {

	struct icmp6_hdr *ihdr = frame + start;

	l->payload_start = start + sizeof(struct icmp6_hdr); 
	l->payload_size = len - sizeof(struct icmp6_hdr);

	match_type_info->val.ui32 = ihdr->icmp6_type;
	match_code_info->val.ui32 = ihdr->icmp6_code;

	if (!(ihdr->icmp6_type & ICMP6_INFOMSG_MASK))
			return match_ipv6_id;
	return -1;
}

int match_layer_info_snprintf_icmpv6(char *buff, unsigned int len, struct layer_info *inf) {


	switch (match_type_info->val.ui32) {
		case ICMP6_ECHO_REQUEST:
			strncpy(buff, "ping", len);
			return 4;
		case ICMP6_ECHO_REPLY:
			strncpy(buff, "pong", len);
			return 4;
	}

	return snprintf(buff, len, "%u", match_type_info->val.ui32);

}
