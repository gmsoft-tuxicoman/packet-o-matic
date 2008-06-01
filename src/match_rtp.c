/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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

static struct match_dep *match_undefined;

static int field_payload, field_ssrc, field_seq, field_timestamp;

static struct ptype *ptype_uint8, *ptype_uint16, *ptype_uint32, *ptype_uint32_hex;

int match_register_rtp(struct match_reg *r) {

	r->identify = match_identify_rtp;
	r->get_expectation = match_get_expectation_rtp;
	r->unregister = match_unregister_rtp;

	match_undefined = match_add_dependency(r->type, "undefined");

	ptype_uint8 = ptype_alloc("uint8", NULL);
	ptype_uint16 = ptype_alloc("uint16", NULL);
	ptype_uint32 = ptype_alloc("uint32", NULL);
	ptype_uint32_hex = ptype_alloc("uint32", NULL);
	ptype_uint32_hex->print_mode = PTYPE_UINT32_PRINT_HEX;

	if (!ptype_uint8 || !ptype_uint16 || !ptype_uint32 || !ptype_uint32_hex) {
		match_unregister_rtp(r);
		return POM_ERR;
	}

	field_payload = match_register_field(r->type, "payload", ptype_uint8, "Payload type");
	field_ssrc = match_register_field(r->type, "ssrc", ptype_uint32, "Syncronization source");
	field_seq = match_register_field(r->type, "seq", ptype_uint16, "Sequence");
	field_timestamp = match_register_field(r->type, "ts", ptype_uint32, "Timestamp");

	return POM_OK;

}

static int match_identify_rtp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct rtphdr *hdr = f->buff + start;


	if (hdr->version != 2)
		return POM_ERR;

	int hdr_len = sizeof(struct rtphdr);
	hdr_len += hdr->csrc_count * 4;

	if (len - hdr_len <= 0) {
		pom_log(POM_LOG_TSHOOT "Invalid size for RTP packet\r\n");
		return POM_ERR;
	}

	PTYPE_UINT8_SETVAL(l->fields[field_payload], hdr->payload_type);
	PTYPE_UINT32_SETVAL(l->fields[field_ssrc], hdr->ssrc);
	PTYPE_UINT16_SETVAL(l->fields[field_seq], ntohs(hdr->seq_num));
	PTYPE_UINT32_SETVAL(l->fields[field_timestamp], ntohl(hdr->timestamp));

	if (hdr->extension) {
		struct rtphdrext *ext;
		ext = f->buff + start + hdr_len;
		hdr_len += ntohs(ext->length);
		if (len < (hdr_len + start)) {
			pom_log(POM_LOG_TSHOOT "Invalid size for RTP packet\r\n");
			return POM_ERR;
		}
	}
	l->payload_start = start + hdr_len;
	l->payload_size = len - hdr_len;

	if (hdr->padding) {
		unsigned int pad = *(((unsigned char*) (f->buff)) + len - 1);
		if (pad > len - sizeof(struct rtphdr))
			return POM_ERR;
		l->payload_size -= pad;
	}


	return match_undefined->id;

}

static int match_get_expectation_rtp(int field_id, int direction) {

	if (field_id == field_ssrc && direction == EXPT_DIR_FWD)
		return field_ssrc;

	return POM_ERR;
}

static int match_unregister_rtp(struct match_reg *r) {

	ptype_cleanup(ptype_uint8);
	ptype_cleanup(ptype_uint16);
	ptype_cleanup(ptype_uint32);
	ptype_cleanup(ptype_uint32_hex);

	return POM_OK;
}
