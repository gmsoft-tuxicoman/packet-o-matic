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



#include "match_rtp.h"
#include "ptype_uint8.h"
#include "ptype_uint32.h"

int match_undefined_id;
struct match_functions *m_functions;
struct layer_info *match_payload_info, *match_seq_info, *match_timestamp_info, *match_ssrc_info;

struct ptype *field_payload, *field_ssrc;

int match_register_rtp(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_rtp;
	r->unregister = match_unregister_rtp;

	m_functions = m_funcs;

	match_undefined_id = (*m_functions->match_register) ("undefined");

	match_payload_info = (*m_funcs->layer_info_register) (r->type, "payload_type", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_HEX);
	match_seq_info = (*m_funcs->layer_info_register) (r->type, "seq", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_HEX);
	match_timestamp_info = (*m_funcs->layer_info_register) (r->type, "timestamp", LAYER_INFO_TYPE_UINT32);
	match_ssrc_info = (*m_funcs->layer_info_register) (r->type, "ssrc", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_HEX);

	field_payload = (*m_funcs->ptype_alloc) ("uint8", NULL);
	field_ssrc = (*m_funcs->ptype_alloc) ("uint32", NULL);

	if (!field_payload || !field_ssrc) {
		match_unregister_rtp(r);
		return POM_ERR;
	}

	(*m_funcs->register_param) (r->type, "payload_type", field_payload, "Payload type");
	(*m_funcs->register_param) (r->type, "ssrc", field_ssrc, "Syncronization source");

	return POM_OK;

}

int match_identify_rtp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct rtphdr *hdr = f->buff + start;

	int hdr_len = sizeof(struct rtphdr);
	hdr_len += hdr->csrc_count * 4;

	if (len - hdr_len <= 0) {
		ndprint("Invalid size for RTP packet\n");
		return -1;
	}

	PTYPE_UINT8_SETVAL(field_payload, hdr->payload_type);
	PTYPE_UINT32_SETVAL(field_ssrc, hdr->ssrc);

	match_payload_info->val.ui32 =  hdr->payload_type;
	match_seq_info->val.ui32 = ntohs(hdr->seq_num);
	match_timestamp_info->val.ui32 = ntohl(hdr->timestamp);
	match_ssrc_info->val.ui32 = hdr->ssrc;

	if (hdr->extension) {
		struct rtphdrext *ext;
		ext = f->buff + start + hdr_len;
		hdr_len += ntohs(ext->length);
		if (len < (hdr_len + start)) {
			ndprint(" Invalid size for RTP packet\n");
			return -1;
		}
	}
	l->payload_start = start + hdr_len;
	l->payload_size = len - hdr_len;

	if (hdr->padding) {
		l->payload_size = *(((unsigned char*) (f->buff)) + len - 1);
	}


	return match_undefined_id;

}
	
int match_unregister_rtp(struct match_reg *r) {
	(*m_functions->ptype_cleanup) (field_payload);
	(*m_functions->ptype_cleanup) (field_ssrc);
	return POM_OK;
}
