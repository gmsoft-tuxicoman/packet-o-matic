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

#ifndef __PTYPE_UINT16_H__
#define __PTYPE_UINT16_H__

#include "modules_common.h"
#include "ptype.h"

/**
 * @ingroup ptypes
 */
/*@{*/

/// Print the value in hexadecimal
#define PTYPE_UINT16_PRINT_DECIMAL	0
/// Print the value in 
#define PTYPE_UINT16_PRINT_HEX		1

/// Get the value from a ptype uint16
/**
 * @param x The struct ptype
 * @return The ptype value.
 */
#define PTYPE_UINT16_GETVAL(x) 			\
	(uint16_t) *((uint16_t*) (x)->value)

/// Set the value of a ptype uint16
/**
 * @param x The struct ptype
 * @param y The value
 */
#define PTYPE_UINT16_SETVAL(x, y) {	\
	uint16_t *v = (x)->value;	\
	*v = (y);			\
}


/*@}*/

int ptype_register_uint16(struct ptype_reg *r);
int ptype_alloc_uint16(struct ptype *p);
int ptype_cleanup_uint16(struct ptype *p);
int ptype_parse_uint16(struct ptype *p, char *val);
int ptype_print_uint16(struct ptype *pt, char *val, size_t size);
int ptype_compare_uint16(int op, void *val_a, void* val_b);
int ptype_copy_uint16(struct ptype *dst, struct ptype *src);

#endif
