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


#include "match_tcp.h"
#include <netinet/tcp.h>

#include "ptype_uint16.h"

int match_undefined_id;
struct match_functions *m_functions;
struct layer_info *match_sport_info, *match_dport_info, *match_flags_info, *match_seq_info, *match_ack_info, *match_win_info;

struct ptype *field_sport, *field_dport;

int match_register_tcp(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_tcp;
	r->unregister = match_unregister_tcp;

	m_functions = m_funcs;

	match_undefined_id = (*m_functions->match_register) ("undefined");

	match_sport_info = (*m_funcs->layer_info_register) (r->type, "sport", LAYER_INFO_TYPE_UINT32);
	match_dport_info = (*m_funcs->layer_info_register) (r->type, "dport", LAYER_INFO_TYPE_UINT32);
	match_flags_info = (*m_funcs->layer_info_register) (r->type, "flags", LAYER_INFO_TYPE_UINT32);
	match_flags_info->snprintf = match_layer_info_snprintf_tcp;
	match_seq_info = (*m_funcs->layer_info_register) (r->type, "seq", LAYER_INFO_TYPE_UINT32);
	match_ack_info = (*m_funcs->layer_info_register) (r->type, "ack", LAYER_INFO_TYPE_UINT32);
	match_win_info = (*m_funcs->layer_info_register) (r->type, "win", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_ZERO);

	field_sport = (*m_funcs->ptype_alloc) ("uint16", NULL);
	field_dport = (*m_funcs->ptype_alloc) ("uint16", NULL);
	if (!field_sport || !field_dport) {
		match_unregister_tcp(r);
		return POM_ERR;
	}

	(*m_funcs->register_param) (r->type, "sport", field_sport, "Source port");
	(*m_funcs->register_param) (r->type, "dport", field_dport, "Destination port");

	return POM_OK;

}


int match_identify_tcp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct tcphdr* hdr = f->buff + start;
	
	unsigned int hdrlen = (hdr->th_off << 2);
	l->payload_start = start + hdrlen;
	l->payload_size = len - hdrlen;

	match_sport_info->val.ui32 = ntohs(hdr->th_sport);
	match_dport_info->val.ui32 = ntohs(hdr->th_dport);
	match_flags_info->val.ui32 = hdr->th_flags;
	match_seq_info->val.ui32 = ntohl(hdr->th_seq);
	match_ack_info->val.ui32 = ntohl(hdr->th_ack);
	match_win_info->val.ui32 = ntohs(hdr->th_win);

	PTYPE_UINT16_SETVAL(field_sport, ntohs(hdr->th_sport));
	PTYPE_UINT16_SETVAL(field_dport, ntohs(hdr->th_dport));

	return match_undefined_id;

}

int match_layer_info_snprintf_tcp(char *buff, unsigned int len, struct layer_info *inf) {

	char buffer[24];
	bzero(buffer, 24);

	if (inf->val.ui32 & TH_FIN) {
		strcat(buffer, "FIN");
	}

	if (inf->val.ui32 & TH_SYN) {
		if (buffer[0])
			strcat(buffer, ",");
		strcat(buffer, "SYN");
	}

	if (inf->val.ui32 & TH_RST) {
		if (buffer[0])
			strcat(buffer, ",");
		strcat(buffer, "RST");
	}

	if (inf->val.ui32 & TH_PUSH) {
		if (buffer[0])
			strcat(buffer, ",");
		strcat(buffer, "PSH");
	}

	if (inf->val.ui32 & TH_ACK) {
		if (buffer[0])
			strcat(buffer, ",");
		strcat(buffer, "ACK");
	}

	if (inf->val.ui32 & TH_URG) {
		if (buffer[0])
			strcat(buffer, ",");
		strcat(buffer, "URG");
	}

	strncpy(buff, buffer, len - 1);

	return strlen(buff);
}

int match_unregister_tcp(struct match_reg *r) {

	(*m_functions->ptype_cleanup) (field_sport);
	(*m_functions->ptype_cleanup) (field_dport);
	return POM_OK;

}
