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

#include "ptype_uint8.h"
#include "ptype_uint16.h"
#include "ptype_uint32.h"

int match_undefined_id;
struct match_functions *mf;

struct match_field_reg *field_sport, *field_dport, *field_flags, *field_seq, *field_ack, *field_win;

struct ptype *ptype_uint8, *ptype_uint16, *ptype_uint32;

int match_register_tcp(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_tcp;
	r->unregister = match_unregister_tcp;

	mf = m_funcs;

	match_undefined_id = (*mf->match_register) ("undefined");

	ptype_uint8 = (*mf->ptype_alloc) ("uint8", NULL);
	ptype_uint16 = (*mf->ptype_alloc) ("uint16", NULL);
	ptype_uint32 = (*mf->ptype_alloc) ("uint32", NULL);
	
	if (!ptype_uint8 || !ptype_uint16 || !ptype_uint32) {
		match_unregister_tcp(r);
		return POM_ERR;
	}

	field_sport = (*mf->register_field) (r->type, "sport", ptype_uint16, "Source port");
	field_dport = (*mf->register_field) (r->type, "dport", ptype_uint16, "Destination port");
	field_flags = (*mf->register_field) (r->type, "flags", ptype_uint8, "Flags");
	field_seq = (*mf->register_field) (r->type, "seq", ptype_uint32, "Sequence");
	field_ack = (*mf->register_field) (r->type, "ack", ptype_uint32, "Sequence ACK");
	field_win = (*mf->register_field) (r->type, "win", ptype_uint16, "Window");


	return POM_OK;

}


int match_identify_tcp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct tcphdr* hdr = f->buff + start;
	
	unsigned int hdrlen = (hdr->th_off << 2);
	l->payload_start = start + hdrlen;
	l->payload_size = len - hdrlen;

	struct layer_field *lf = l->fields;
	while (lf) {
		if (lf->type == field_sport) {
			PTYPE_UINT16_SETVAL(lf->value, ntohs(hdr->th_sport));
		} else if (lf->type == field_dport) {
			PTYPE_UINT16_SETVAL(lf->value, ntohs(hdr->th_dport));
		} else if (lf->type == field_flags) {
			PTYPE_UINT8_SETVAL(lf->value, hdr->th_flags);
		} else if (lf->type == field_seq) {
			PTYPE_UINT32_SETVAL(lf->value, ntohl(hdr->th_seq));
		} else if (lf->type == field_ack) {
			PTYPE_UINT32_SETVAL(lf->value, ntohl(hdr->th_ack));
		} else if (lf->type == field_win) {
			PTYPE_UINT16_SETVAL(lf->value, ntohs(hdr->th_win));
		}
		lf = lf->next;
	}

	return match_undefined_id;

}

int match_unregister_tcp(struct match_reg *r) {

	(*mf->ptype_cleanup) (ptype_uint8);
	(*mf->ptype_cleanup) (ptype_uint16);
	(*mf->ptype_cleanup) (ptype_uint32);

	return POM_OK;
}
