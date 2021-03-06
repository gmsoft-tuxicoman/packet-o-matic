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


#ifndef __MATCH_IPV6_H__
#define __MATCH_IPV6_H__


#include "modules_common.h"
#include "match.h"
#include <netinet/in.h>
#include <netinet/ip6.h>

// Generic extension header
struct ip6_ehdr {
	uint8_t ip6e_nxt; // next header
	uint8_t ip6e_len; // length in units of 8 bytes
};

int match_register_ipv6(struct match_reg *r);
static int match_identify_ipv6(struct frame *f, struct layer* l, unsigned int start, unsigned int len);
static int match_get_expectation_ipv6(int field_id, int direction);
static int match_unregister_ipv6(struct match_reg *r);

#endif
