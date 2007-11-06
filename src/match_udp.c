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

#include "match_udp.h"
#include <netinet/udp.h>

#include "ptype_uint16.h"

int match_undefined_id;
struct match_functions *mf;

struct match_field_reg *field_sport, *field_dport;

struct ptype *ptype_uint16;

int match_register_udp(struct match_reg *r, struct match_functions *m_funcs) {


	r->identify = match_identify_udp;
	r->unregister = match_unregister_udp;

	mf = m_funcs;

	match_undefined_id = (*mf->match_register) ("undefined");

	ptype_uint16 = (*mf->ptype_alloc) ("uint16", NULL);

	if (!ptype_uint16)
		return POM_ERR;

	field_sport = (*mf->register_field) (r->type, "sport", ptype_uint16, "Source port");
	field_dport = (*mf->register_field) (r->type, "dport", ptype_uint16, "Destination port");


	return POM_OK;

}


int match_identify_udp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {
	struct udphdr *hdr = f->buff + start;

	l->payload_start = start + sizeof(struct udphdr);
	l->payload_size = ntohs(hdr->uh_ulen) - sizeof(struct udphdr);

	struct layer_field *lf = l->fields;
	while (lf) {
		if (lf->type == field_sport) {
			PTYPE_UINT16_SETVAL(lf->value, ntohs(hdr->uh_sport));
		} else if (lf->type == field_dport) {
			PTYPE_UINT16_SETVAL(lf->value, ntohs(hdr->uh_dport));
		}
		lf = lf->next;
	}


	return match_undefined_id;

}

int match_unregister_udp(struct match_reg *r) {

	(*mf->ptype_cleanup) (ptype_uint16);
	return POM_OK;

}
