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

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "match_icmpv6.h"
#include "ptype_uint8.h"

static struct match_dep *match_undefined;

static int field_type, field_code;

static struct ptype *ptype_uint8;

int match_register_icmpv6(struct match_reg *r) {

	r->identify = match_identify_icmpv6;
	r->unregister = match_unregister_icmpv6;

	match_undefined = match_add_dependency(r->type, "undefined");

	ptype_uint8 = ptype_alloc("uint8", NULL);

	if (!ptype_uint8)
		return POM_ERR;

	field_type = match_register_field(r->type, "type", ptype_uint8, "Type");
	field_code = match_register_field(r->type, "code", ptype_uint8, "Code");

	return POM_OK;
}

static int match_identify_icmpv6(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct icmp6_hdr *ihdr = f->buff + start;

	if (sizeof(struct icmp6_hdr) > len)
		return POM_ERR;

	l->payload_start = start + sizeof(struct icmp6_hdr); 
	l->payload_size = len - sizeof(struct icmp6_hdr);

	PTYPE_UINT8_SETVAL(l->fields[field_type], ihdr->icmp6_type);
	PTYPE_UINT8_SETVAL(l->fields[field_code], ihdr->icmp6_code);

	/* For now we don't advertise the ip layer
	if (!(ihdr->icmp6_type & ICMP6_INFOMSG_MASK))
			return match_ipv6->id;
	*/
	return match_undefined->id;
}

static int match_unregister_icmpv6(struct match_reg *r) {

	ptype_cleanup(ptype_uint8);
	return POM_OK;

}
