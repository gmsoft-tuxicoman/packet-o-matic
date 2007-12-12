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

#ifndef __PTYPE_BYTES_H__
#define __PTYPE_BYTES_H__

#include "modules_common.h"
#include "ptype.h"

struct ptype_bytes_val {
	size_t length;
	unsigned char *value;
	unsigned char *mask;
};

// x is the struct ptype, y is the new length
#define PTYPE_BYTES_SETLEN(x, y) { 				\
	struct ptype_bytes_val *v = (x)->value;			\
	if (v->length != (y)) {					\
		if ((y) == 0) {					\
			if (v->value) {				\
				free(v->value);			\
				v->value = NULL;		\
			}					\
			if (v->mask) {				\
				free(v->mask);			\
				v->mask = NULL;			\
			}					\
		} else {					\
			v->value = realloc(v->value, (y));	\
			bzero(v->value, (y));			\
			v->mask = realloc(v->mask, (y));	\
			memset(v->mask, 0xff, (y));		\
		}						\
		v->length = (y);				\
	}							\
}								\

// x is the struct ptype, y are the bytes
#define PTYPE_BYTES_SETVAL(x, y) {			\
	struct ptype_bytes_val *v = (x)->value;		\
	memcpy(v->value, y, v->length);			\
}

// x is the struct ptype, y are the bytes
#define PTYPE_BYTES_SETMASK(x, y) {			\
	struct ptype_bytes_val *v = (x)->value;		\
	memcpy(v->mask, y, v->length);			\
}

int ptype_register_bytes(struct ptype_reg *r);
int ptype_alloc_bytes(struct ptype *p);
int ptype_cleanup_bytes(struct ptype *p);
int ptype_parse_bytes(struct ptype *p, char *val);
int ptype_print_bytes(struct ptype *pt, char *val, size_t size);
int ptype_compare_bytes(int op, void *val_a, void *val_b);

#endif
