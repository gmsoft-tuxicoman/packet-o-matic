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
#include "ptype_bytes.h"

int match_ipv4_id, match_ipv6_id;
struct match_functions *mf;

int field_pkt_type, field_ha_type, field_addr;

struct ptype *ptype_uint16, *ptype_bytes;

int match_register_linux_cooked(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_linux_cooked;
	r->unregister = match_unregister_linux_cooked;

	mf = m_funcs;
	
	match_ipv4_id = (*mf->match_register) ("ipv4");
	match_ipv6_id = (*mf->match_register) ("ipv6");

	ptype_uint16 = (*mf->ptype_alloc) ("uint16", NULL);
	ptype_bytes = (*mf->ptype_alloc) ("bytes", NULL);

	if (!ptype_uint16 || !ptype_bytes) {
		match_unregister_linux_cooked(r);
		return POM_ERR;
	}

	field_pkt_type = (*mf->register_field) (r->type, "pkt_type", ptype_uint16, "Packet type");
	field_ha_type = (*mf->register_field) (r->type, "ha_type", ptype_uint16, "Address type");
	field_addr = (*mf->register_field) (r->type, "src", ptype_bytes, "Source address");


	return POM_OK;
}

int match_identify_linux_cooked(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct sll_header *chdr = f->buff + start;

	uint16_t addr_len = ntohs(chdr->sll_halen);
	if (addr_len > SLL_ADDRLEN)
		return -1;

	l->payload_start = start + sizeof(struct sll_header);
	l->payload_size = len - sizeof(struct sll_header);

	PTYPE_UINT16_SETVAL(l->fields[field_pkt_type], ntohs(chdr->sll_pkttype));
	PTYPE_UINT16_SETVAL(l->fields[field_ha_type], ntohs(chdr->sll_hatype));

	PTYPE_BYTES_SETLEN(l->fields[field_addr], addr_len);
	PTYPE_BYTES_SETVAL(l->fields[field_addr], chdr->sll_addr);

	switch (ntohs(chdr->sll_protocol)) {
		case 0x0800:
			return  match_ipv4_id;
		case 0x86dd:
			return match_ipv6_id;
	}

	return POM_ERR;
}

int match_unregister_linux_cooked(struct match_reg *r) {

	(*mf->ptype_cleanup) (ptype_uint16);
	(*mf->ptype_cleanup) (ptype_bytes);
	return POM_OK;

}
