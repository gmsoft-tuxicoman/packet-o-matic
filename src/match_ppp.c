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


#include "match_ppp.h"

static struct match_dep *match_undefined, *match_ipv4, *match_ipv6;

int match_register_ppp(struct match_reg *r) {

	r->identify = match_identify_ppp;
	
	match_undefined = match_add_dependency(r->type, "undefined");
	match_ipv4 = match_add_dependency(r->type, "ipv4");
	match_ipv6 = match_add_dependency(r->type, "ipv6");

	return POM_OK;

}

static int match_identify_ppp(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {


	if (sizeof(uint16_t) > len)
		return POM_ERR;

	uint16_t *ppp_hdr = f->buff + start;
	uint16_t proto = ntohs(*ppp_hdr);

	l->payload_start = start + sizeof(uint16_t);
	l->payload_size = len - sizeof(uint16_t);

	switch (proto) {
		case 0x21: // IPv4
			return match_ipv4->id;
		case 0x57: // IPv6
			return match_ipv6->id;
	}

	return match_undefined->id;
}
