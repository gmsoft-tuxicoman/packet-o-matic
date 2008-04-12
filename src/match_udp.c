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

#include "match_udp.h"
#include <netinet/udp.h>

#include "ptype_uint16.h"

struct match_dep *match_undefined;
struct match_functions *mf;

int field_sport, field_dport;

struct ptype *ptype_uint16;

int match_register_udp(struct match_reg *r, struct match_functions *m_funcs) {


	r->identify = match_identify_udp;
	r->get_expectation = match_get_expectation_udp;
	r->unregister = match_unregister_udp;

	mf = m_funcs;

	match_undefined = (*mf->add_dependency) (r->type, "undefined");

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

	PTYPE_UINT16_SETVAL(l->fields[field_sport], ntohs(hdr->uh_sport));
	PTYPE_UINT16_SETVAL(l->fields[field_dport], ntohs(hdr->uh_dport));

	return match_undefined->id;

}

int match_get_expectation_udp(int field_id, int direction) {

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

int match_unregister_udp(struct match_reg *r) {

	(*mf->ptype_cleanup) (ptype_uint16);
	return POM_OK;

}
