/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __PTYPE_IPV4_H__
#define __PTYPE_IPV4_H__

#include "modules_common.h"
#include "ptype.h"


struct ptype_ipv6_val {
	struct in6_addr addr;
	unsigned char mask;
};


/// x is the struct ptype
#define PTYPE_IPV6_GETVAL(x) \
	((struct ptype_ipv6_val*) x->addr

/// x is the struct ptype, y the ipv4
#define PTYPE_IPV6_SETADDR(x, y) { \
	struct ptype_ipv6_val *v = (x)->value;\
	memcpy(&v->addr, &y, sizeof(struct in6_addr)); \
}

int ptype_register_ipv6(struct ptype_reg *r);
int ptype_alloc_ipv6(struct ptype *p);
int ptype_cleanup_ipv6(struct ptype *p);
int ptype_parse_ipv6(struct ptype *p, char *val);
int ptype_print_ipv6(struct ptype *pt, char *val, size_t size);
int ptype_compare_ipv6(int op, void *val_a, void *val_b);

#endif
