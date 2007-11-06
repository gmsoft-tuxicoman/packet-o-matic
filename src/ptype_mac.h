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

#ifndef __PTYPE_MAC_H__
#define __PTYPE_MAC_H__

#include "modules_common.h"
#include "ptype.h"

struct ptype_mac_val {
	char addr[6];
	char mask[6];
};

// x is the struct ptype, y the mac
#define PTYPE_MAC_SETADDR(x, y) { \
	struct ptype_mac_val *v = (x)->value;\
	memcpy(v->addr, y, 6); \
}


int ptype_register_mac(struct ptype_reg *r);
int ptype_alloc_mac(struct ptype* p);
int ptype_cleanup_mac(struct ptype *p);
int ptype_parse_mac(struct ptype *p, char *val);
int ptype_print_mac(struct ptype *pt, char *val, size_t size);
int ptype_compare_mac(int op, void *val_a, void *val_b);

#endif
