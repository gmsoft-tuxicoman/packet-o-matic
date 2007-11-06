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

#include "match_linux_cooked.h"
#include "ptype_uint16.h"

int match_ipv4_id, match_ipv6_id;
struct match_functions *mf;

struct match_field_reg *field_pkt_type, *field_dev_type, *field_saddr;

struct ptype *ptype_uint16;

int match_register_linux_cooked(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_linux_cooked;
	r->unregister = match_unregister_linux_cooked;

	mf = m_funcs;
	
	match_ipv4_id = (*mf->match_register) ("ipv4");
	match_ipv6_id = (*mf->match_register) ("ipv6");

	ptype_uint16 = (*mf->ptype_alloc) ("uint16", NULL);

	if (!ptype_uint16)
		return POM_ERR;

	field_pkt_type = (*mf->register_field) (r->type, "pkt_type", ptype_uint16, "Packet type");
	field_dev_type = (*mf->register_field) (r->type, "dev_type", ptype_uint16, "Device type");
	field_saddr = (*mf->register_field) (r->type, "src", ptype_uint16, "Source address");

	return POM_OK;
}

int match_identify_linux_cooked(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct cooked_hdr *chdr = f->buff + start;

	l->payload_start = start + sizeof(struct cooked_hdr);
	l->payload_size = len - sizeof(struct cooked_hdr);

	struct layer_field *lf = l->fields;
	while (lf) {
		if (lf->type == field_pkt_type) {
			PTYPE_UINT16_SETVAL(lf->value, ntohs(chdr->pkt_type));
		} else if (lf->type == field_dev_type) {
			PTYPE_UINT16_SETVAL(lf->value, ntohs(chdr->dev_type));
		} else if (lf->type == field_saddr) {
			PTYPE_UINT16_SETVAL(lf->value, ntohs(chdr->ll_saddr));
		}

		lf = lf->next;
	}

	switch (ntohs(chdr->ether_type)) {
		case 0x0800:
			return  match_ipv4_id;
		case 0x86dd:
			return match_ipv6_id;
	}

	return POM_ERR;
}

int match_unregister_linux_cooked(struct match_reg *r) {

	(*mf->ptype_cleanup) (ptype_uint16);
	return POM_OK;

}
