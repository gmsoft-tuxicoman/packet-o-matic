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

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>


struct ptype_ipv4_val {
	struct in_addr addr;
	unsigned char mask;
};


/// x is the struct ptype
#define PTYPE_IPV4_GETADDR(x) \
	((struct ptype_ipv4_val*) x)->addr

/// x is the struct ptype, y the ipv4
#define PTYPE_IPV4_SETADDR(x, y) { \
	struct ptype_ipv4_val *v = (x)->value; \
	memcpy(&v->addr, &y, sizeof(struct in_addr)); \
}



int ptype_register_ipv4(struct ptype_reg *r);
int ptype_alloc_ipv4(struct ptype *p);
int ptype_cleanup_ipv4(struct ptype *p);
int ptype_parse_ipv4(struct ptype *p, char *val);
int ptype_print_ipv4(struct ptype *pt, char *val, size_t size);
int ptype_compare_ipv4(int op, void *val_a, void *val_b);
int ptype_copy_ipv4(struct ptype *dst, struct ptype *src);

#endif
