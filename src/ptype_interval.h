/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2008 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __PTYPE_INTERVAL_H__
#define __PTYPE_INTERVAL_H__

#include "modules_common.h"
#include "ptype.h"

#define PTYPE_INTERVAL_PRINT_NORMAL	0

/// x the struct ptype
#define PTYPE_INTERVAL_GETVAL(x) 			\
	(time_t) *((time_t*) (x)->value)

/// x is the struct ptype, y the value
#define PTYPE_INTERVAL_SETVAL(x, y) {	\
	time_t *v = (x)->value;	\
	*v = (y);			\
}

int ptype_register_interval(struct ptype_reg *r);
int ptype_alloc_interval(struct ptype *p);
int ptype_cleanup_interval(struct ptype *p);
int ptype_parse_interval(struct ptype *p, char *val);
int ptype_print_interval(struct ptype *pt, char *val, size_t size);
int ptype_compare_interval(int op, void *val_a, void* val_b);
int ptype_serialize_interval(struct ptype *p, char *val, size_t size);
int ptype_copy_interval(struct ptype *dst, struct ptype *src);


#endif
