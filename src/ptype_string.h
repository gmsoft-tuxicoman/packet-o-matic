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

#ifndef __PTYPE_STRING_H__
#define __PTYPE_STRING_H__

#include "modules_common.h"
#include "ptype.h"

/// x is the struct ptype
#define PTYPE_STRING_GETVAL(x) \
	(char*) x->value

/// x is the struct ptype, y the string
#define PTYPE_STRING_SETVAL(x, y) {		\
	if ((x)->value)				\
		free((x)->value);		\
	char *str = malloc(strlen((y)) + 1);	\
	strcpy(str, (y));			\
	(x)->value = str;			\
}

/// x is the struct ptype, y the string pointer
#define PTYPE_STRING_SETVAL_P(x, y) {		\
	if ((x)->value)				\
		free((x)->value);		\
	(x)->value = y;			\
}

int ptype_register_string(struct ptype_reg *r);
int ptype_cleanup_string(struct ptype *p);
int ptype_parse_string(struct ptype *p, char *val);
int ptype_print_string(struct ptype *pt, char *val, size_t size);
int ptype_compare_string(int op, void *val_a, void *val_b);
int ptype_copy_string(struct ptype *dst, struct ptype *src);

#endif
