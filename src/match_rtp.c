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
#include "ptype_uint16.h"
#include "ptype_uint32.h"

int match_undefined_id;
struct match_functions *mf;

struct match_field_reg *field_payload, *field_ssrc, *field_seq, *field_timestamp;

struct ptype *ptype_uint8, *ptype_uint16, *ptype_uint32;

int match_register_rtp(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_rtp;
	r->unregister = match_unregister_rtp;

	mf = m_funcs;

	match_undefined_id = (*mf->match_register) ("undefined");

	ptype_uint8 = (*mf->ptype_alloc) ("uint8", NULL);
	ptype_uint16 = (*mf->ptype_alloc) ("uint16", NULL);
	ptype_uint32 = (*mf->ptype_alloc) ("uint32", NULL);

	if (!ptype_uint8 || !ptype_uint16 || !ptype_uint32) {
		match_unregister_rtp(r);
		return POM_ERR;
	}

	field_payload = (*mf->register_field) (r->type, "payload", ptype_uint8, "Payload type");
	field_ssrc = (*mf->register_field) (r->type, "ssrc", ptype_uint32, "Syncronization source");
	field_seq = (*mf->register_field) (r->type, "seq", ptype_uint16, "Sequence");
	field_timestamp = (*mf->register_field) (r->type, "ts", ptype_uint32, "Timestamp");

	return POM_OK;

}

int match_identify_rtp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct rtphdr *hdr = f->buff + start;

	int hdr_len = sizeof(struct rtphdr);
	hdr_len += hdr->csrc_count * 4;

	if (len - hdr_len <= 0) {
		(*mf->pom_log) (POM_LOG_TSHOOT "Invalid size for RTP packet\r\n");
		return POM_ERR;
	}

	struct layer_field *lf = l->fields;
	while (lf) {
		if (lf->type == field_payload) {
			PTYPE_UINT8_SETVAL(lf->value, hdr->payload_type);
		} else if (lf->type == field_ssrc) {
			PTYPE_UINT32_SETVAL(lf->value, hdr->ssrc);
		} else if (lf->type == field_seq) {
			PTYPE_UINT16_SETVAL(lf->value, ntohs(hdr->seq_num));
		} else if (lf->type == field_timestamp) {
			PTYPE_UINT32_SETVAL(lf->value, ntohl(hdr->timestamp));
		}
		lf = lf->next;
	}

	if (hdr->extension) {
		struct rtphdrext *ext;
		ext = f->buff + start + hdr_len;
		hdr_len += ntohs(ext->length);
		if (len < (hdr_len + start)) {
			(*mf->pom_log) (POM_LOG_TSHOOT "Invalid size for RTP packet\r\n");
			return POM_ERR;
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

	(*mf->ptype_cleanup) (ptype_uint8);
	(*mf->ptype_cleanup) (ptype_uint16);
	(*mf->ptype_cleanup) (ptype_uint32);

	return POM_OK;
}
