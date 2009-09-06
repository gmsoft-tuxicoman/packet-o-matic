/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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


#include "match_pppoe.h"
#include "ptype_uint8.h"
#include "ptype_uint16.h"


static struct match_dep *match_undefined, *match_ppp;

static int field_code, field_sess_id;

static struct ptype *ptype_uint8, *ptype_uint16;

int match_register_pppoe(struct match_reg *r) {

	r->identify = match_identify_pppoe;
	r->unregister = match_unregister_pppoe;
	
	match_undefined = match_add_dependency(r->type, "undefined");
	match_ppp = match_add_dependency(r->type, "ppp");

	ptype_uint8 = ptype_alloc("uint8", NULL);
	ptype_uint8->print_mode = PTYPE_UINT8_PRINT_HEX;
	ptype_uint16 = ptype_alloc("uint16", NULL);

	if (!ptype_uint8 || !ptype_uint16) {
		match_unregister_pppoe(r);
		return POM_ERR;
	}

	field_code = match_register_field(r->type, "code", ptype_uint8, "Code");
	field_sess_id = match_register_field(r->type, "session", ptype_uint16, "Session ID");

	return POM_OK;

}

static int match_identify_pppoe(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {


	if (sizeof(struct pppoe_hdr) > len)
		return POM_ERR;

	struct pppoe_hdr *phdr = f->buff + start;

	uint16_t plen = ntohs(phdr->len);

	if (plen > len - sizeof(struct pppoe_hdr))
		return POM_ERR;

	l->payload_start = start + sizeof(struct pppoe_hdr);
	l->payload_size = plen;


	PTYPE_UINT8_SETVAL(l->fields[field_code], phdr->code);
	PTYPE_UINT16_SETVAL(l->fields[field_sess_id], ntohs(phdr->sess_id));

	if (!phdr->code)
		return match_ppp->id;

	return match_undefined->id;
}

static int match_unregister_pppoe(struct match_reg *r) {

	if (ptype_uint8)
		ptype_cleanup(ptype_uint8);
	if (ptype_uint16)
		ptype_cleanup(ptype_uint16);

	return POM_OK;
}
