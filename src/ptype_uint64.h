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

#ifndef __PTYPE_UINT64_H__
#define __PTYPE_UINT64_H__

#include "modules_common.h"
#include "ptype.h"

#define PTYPE_UINT64_PRINT_DECIMAL	0
#define PTYPE_UINT64_PRINT_HEX		1
#define PTYPE_UINT64_PRINT_HUMAN	2
#define PTYPE_UINT64_PRINT_HUMAN_1024	4

/// x the struct ptype
#define PTYPE_UINT64_GETVAL(x) 			\
	(uint64_t) *((uint64_t*) (x)->value)

/// x is the struct ptype, y the value
#define PTYPE_UINT64_SETVAL(x, y) {	\
	uint64_t *v = (x)->value;	\
	*v = (y);			\
}

/// x is the struct ptype, y the increment
#define PTYPE_UINT64_INC(x, y) 		\
	*((uint64_t*)(x)->value) += (uint64_t) (y)	


int ptype_register_uint64(struct ptype_reg *r);
int ptype_alloc_uint64(struct ptype *p);
int ptype_cleanup_uint64(struct ptype *p);
int ptype_parse_uint64(struct ptype *p, char *val);
int ptype_print_uint64(struct ptype *pt, char *val, size_t size);
int ptype_compare_uint64(int op, void *val_a, void* val_b);
int ptype_serialize_uint64(struct ptype *p, char *val, size_t size);
int ptype_copy_uint64(struct ptype *dst, struct ptype *src);

#endif
