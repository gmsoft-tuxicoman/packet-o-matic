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
struct match_functions *m_functions;
struct layer_info *match_sport_info, *match_dport_info;

struct ptype *field_sport, *field_dport;

int match_register_udp(struct match_reg *r, struct match_functions *m_funcs) {


	r->identify = match_identify_udp;
	r->unregister = match_unregister_udp;

	m_functions = m_funcs;

	match_undefined_id = (*m_functions->match_register) ("undefined");

	match_sport_info = (*m_funcs->layer_info_register) (r->type, "sport", LAYER_INFO_TYPE_UINT32);
	match_dport_info = (*m_funcs->layer_info_register) (r->type, "dport", LAYER_INFO_TYPE_UINT32);

	field_sport = (*m_funcs->ptype_alloc) ("uint16", NULL);
	field_dport = (*m_funcs->ptype_alloc) ("uint16", NULL);
	if (!field_sport || !field_dport) {
		match_unregister_udp(r);
		return POM_ERR;
	}

	(*m_funcs->register_param) (r->type, "sport", field_sport, "Source port");
	(*m_funcs->register_param) (r->type, "dport", field_dport, "Destination port");


	return POM_OK;

}


int match_identify_udp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {
	struct udphdr *hdr = f->buff + start;

	l->payload_start = start + sizeof(struct udphdr);
	l->payload_size = ntohs(hdr->uh_ulen) - sizeof(struct udphdr);

	PTYPE_UINT16_SETVAL(field_sport, ntohs(hdr->uh_sport));
	PTYPE_UINT16_SETVAL(field_dport, ntohs(hdr->uh_dport));

	match_sport_info->val.ui32 = ntohs(hdr->uh_sport);
	match_dport_info->val.ui32 = ntohs(hdr->uh_dport);

	return match_undefined_id;

}


int match_unregister_udp(struct match_reg *r) {

	(*m_functions->ptype_cleanup) (field_sport);
	(*m_functions->ptype_cleanup) (field_dport);
	return POM_OK;
}
