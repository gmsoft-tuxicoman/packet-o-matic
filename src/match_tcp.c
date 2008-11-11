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


#include "match_tcp.h"
#include "ptype_uint8.h"
#include "ptype_uint16.h"
#include "ptype_uint32.h"

#define __FAVOR_BSD // We use BSD favor of the tcp header
#include <netinet/tcp.h>

static struct match_dep *match_undefined;

static int field_sport, field_dport, field_flags, field_seq, field_ack, field_win;

static struct ptype *ptype_uint8, *ptype_uint16, *ptype_uint32;

int match_register_tcp(struct match_reg *r) {

	r->identify = match_identify_tcp;
	r->get_expectation = match_get_expectation_tcp;
	r->unregister = match_unregister_tcp;

	match_undefined = match_add_dependency(r->type, "undefined");

	ptype_uint8 = ptype_alloc("uint8", NULL);
	ptype_uint8->print_mode = PTYPE_UINT8_PRINT_HEX;
	ptype_uint16 = ptype_alloc("uint16", NULL);
	ptype_uint32 = ptype_alloc("uint32", NULL);
	
	if (!ptype_uint8 || !ptype_uint16 || !ptype_uint32) {
		match_unregister_tcp(r);
		return POM_ERR;
	}

	field_sport = match_register_field(r->type, "sport", ptype_uint16, "Source port");
	field_dport = match_register_field(r->type, "dport", ptype_uint16, "Destination port");
	field_flags = match_register_field(r->type, "flags", ptype_uint8, "Flags");
	field_seq = match_register_field(r->type, "seq", ptype_uint32, "Sequence");
	field_ack = match_register_field(r->type, "ack", ptype_uint32, "Sequence ACK");
	field_win = match_register_field(r->type, "win", ptype_uint16, "Window");

	return POM_OK;
}


static int match_identify_tcp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	if (len < sizeof(struct tcphdr))
		return POM_ERR;

	struct tcphdr* hdr = f->buff + start;
	
	unsigned int hdrlen = (hdr->th_off << 2);

	if (hdrlen > len)
		return POM_ERR; // Incomplete packet

	l->payload_start = start + hdrlen;
	l->payload_size = len - hdrlen;


	PTYPE_UINT16_SETVAL(l->fields[field_sport], ntohs(hdr->th_sport));
	PTYPE_UINT16_SETVAL(l->fields[field_dport], ntohs(hdr->th_dport));
	PTYPE_UINT8_SETVAL(l->fields[field_flags], hdr->th_flags);
	PTYPE_UINT32_SETVAL(l->fields[field_seq], ntohl(hdr->th_seq));
	PTYPE_UINT32_SETVAL(l->fields[field_ack], ntohl(hdr->th_ack));
	PTYPE_UINT16_SETVAL(l->fields[field_win], ntohs(hdr->th_win));

	return match_undefined->id;

}

static int match_get_expectation_tcp(int field_id, int direction) {

	if (field_id == field_sport) {
		if (direction == EXPT_DIR_FWD) {
			return field_sport;
		} else {
			return field_dport;
		}
	} else if (field_id == field_dport) {
		if (direction == EXPT_DIR_FWD) {
			return field_dport;
		} else {
			return field_sport;
		}

	}
	return POM_ERR;
}

static int match_unregister_tcp(struct match_reg *r) {

	ptype_cleanup(ptype_uint8);
	ptype_cleanup(ptype_uint16);
	ptype_cleanup(ptype_uint32);

	return POM_OK;
}
