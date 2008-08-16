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

#include "match_icmp.h"
#include "ptype_uint8.h"

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

static struct match_dep *match_ipv4;
static int field_type, field_code;

static struct ptype *ptype_uint8;

int match_register_icmp(struct match_reg *r) {

	r->identify = match_identify_icmp;
	r->unregister = match_unregister_icmp;

	match_ipv4 = match_add_dependency(r->type, "ipv4");

	ptype_uint8 = ptype_alloc("uint8", NULL);

	if (!ptype_uint8)
		return POM_ERR;


	field_type = match_register_field(r->type, "type", ptype_uint8, "Type");
	field_code = match_register_field(r->type, "code", ptype_uint8, "Code");

	return POM_OK;
}

static int match_identify_icmp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct icmp *ihdr = f->buff + start;

	l->payload_start = start + 8; 
	l->payload_size = len - 8;

	PTYPE_UINT8_SETVAL(l->fields[field_type], ihdr->icmp_type);
	PTYPE_UINT8_SETVAL(l->fields[field_code], ihdr->icmp_code);

	return POM_ERR;
}

static int match_unregister_icmp(struct match_reg *r) {

	ptype_cleanup(ptype_uint8);
	return POM_OK;

}

