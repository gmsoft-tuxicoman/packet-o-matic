/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2009 Guy Martin <gmsoft@tuxicoman.be>
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

#include "helper_ipv6.h"

#include <netinet/in.h>
#include <netinet/ip6.h>


int helper_register_ipv6(struct helper_reg *r) {
	
	r->resize = helper_resize_ipv6;
	return POM_OK;

}

static int helper_resize_ipv6(struct frame *f, unsigned int start, unsigned int new_psize) {

	struct ip6_hdr *hdr = f->buff + start;

	hdr->ip6_plen = htons(new_psize);

	return POM_OK;
}

