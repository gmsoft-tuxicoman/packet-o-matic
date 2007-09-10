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

#include "match_icmp.h"
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

int match_ipv4_id;
struct match_functions *m_functions;
struct layer_info *match_type_info, *match_code_info, *match_seq_info;

int match_register_icmp(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_icmp;

	m_functions = m_funcs;
	
	match_ipv4_id = (*m_functions->match_register) ("ipv4");

	match_type_info = (*m_funcs->layer_info_register) (r->type, "type", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_ZERO);
	match_type_info->snprintf = match_layer_info_snprintf_icmp;
	match_code_info = (*m_funcs->layer_info_register) (r->type, "code", LAYER_INFO_TYPE_UINT32);
	match_seq_info = (*m_funcs->layer_info_register) (r->type, "seq", LAYER_INFO_TYPE_UINT32);

	return POM_OK;
}

int match_identify_icmp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct icmp *ihdr = f->buff + start;

	l->payload_start = start + 8; 
	l->payload_size = len - 8;

	match_type_info->val.ui32 = ihdr->icmp_type;
	match_code_info->val.ui32 = ihdr->icmp_code;

	switch (ihdr->icmp_type) {
		case ICMP_ECHOREPLY:
		case ICMP_ECHO:
			match_seq_info->val.ui32 = ntohs(ihdr->icmp_seq);
			return -1;

		case ICMP_TSTAMP:
		case ICMP_TSTAMPREPLY:
		case ICMP_IREQ:
		case ICMP_IREQREPLY:
			match_seq_info->val.ui32 = 0;
			return -1;
	}

	match_seq_info->val.ui32 = 0;
	// For now we don't advertise the ip layer
	//return  match_ipv4_id;
	return -1;
}

int match_layer_info_snprintf_icmp(char *buff, unsigned int len, struct layer_info *inf) {


        switch (match_type_info->val.ui32) {
                case ICMP_ECHO:
                        strncpy(buff, "ping", len);
                        return 4;
                case ICMP_ECHOREPLY:
                        strncpy(buff, "pong", len);
                        return 4;
        }

        return snprintf(buff, len, "%u", match_type_info->val.ui32);

}

