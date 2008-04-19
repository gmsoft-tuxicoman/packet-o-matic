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



#include "ptype_uint8.h"


int ptype_register_uint8(struct ptype_reg *r) {

	r->alloc = ptype_alloc_uint8;
	r->cleanup = ptype_cleanup_uint8;
	r->parse_val = ptype_parse_uint8;
	r->print_val = ptype_print_uint8;
	r->compare_val = ptype_compare_uint8;

	r->serialize = ptype_print_uint8;
	r->unserialize = ptype_parse_uint8;

	r->copy = ptype_copy_uint8;

	r->ops = PTYPE_OP_ALL;

	return POM_OK;

}

int ptype_alloc_uint8(struct ptype *p) {

	p->value = malloc(sizeof(uint8_t));
	uint8_t *v = p->value;
	*v = 0;

	return POM_OK;

}


int ptype_cleanup_uint8(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_parse_uint8(struct ptype *p, char *val) {


	uint8_t *v = p->value;
	if (sscanf(val, "0x%hhx", v) == 1)
		return POM_OK;
	if (sscanf(val, "%hhu", v) == 1)
		return POM_OK;

	return POM_ERR;

};

int ptype_print_uint8(struct ptype *p, char *val, size_t size) {

	uint8_t *v = p->value;

	switch (p->print_mode) {
		case PTYPE_UINT8_PRINT_HEX:
			return snprintf(val, size, "0x%X", *v);
		default:
		case PTYPE_UINT8_PRINT_DECIMAL:
			return snprintf(val, size, "%u", *v);
	}

	return 0;

}

int ptype_compare_uint8(int op, void *val_a, void* val_b) {

	uint8_t *a = val_a;
	uint8_t *b = val_b;

	switch (op) {
		case PTYPE_OP_EQ:
			return *a == *b;
		case PTYPE_OP_GT:
			return *a > *b;
		case PTYPE_OP_GE:
			return *a >= *b;
		case PTYPE_OP_LT:
			return *a < *b;
		case PTYPE_OP_LE:
			return *a <= *b;

	}

	return 0;
}

int ptype_copy_uint8(struct ptype *dst, struct ptype *src) {

	*((uint8_t*)dst->value) = *((uint8_t*)src->value);
	return POM_OK;
}
