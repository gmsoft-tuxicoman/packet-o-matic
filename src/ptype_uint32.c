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



#include "ptype_uint32.h"


int ptype_register_uint32(struct ptype_reg *r) {

	r->alloc = ptype_alloc_uint32;
	r->cleanup = ptype_cleanup_uint32;
	r->parse_val = ptype_parse_uint32;
	r->print_val = ptype_print_uint32;
	r->compare_val = ptype_compare_uint32;
	
	r->serialize = ptype_serialize_uint32;
	r->unserialize = ptype_parse_uint32;

	r->copy = ptype_copy_uint32;
	
	r->ops = PTYPE_OP_ALL;

	return POM_OK;

}

int ptype_alloc_uint32(struct ptype *p) {

	p->value = malloc(sizeof(uint32_t));
	uint32_t *v = p->value;
	*v = 0;

	return POM_OK;

}


int ptype_cleanup_uint32(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_parse_uint32(struct ptype *p, char *val) {


	uint32_t *v = p->value;
	if (sscanf(val, "0x%x", v) == 1) {
		return POM_OK;
	} else if (sscanf(val, "%uk", v) == 1) {
		*v *= 1000;
		char suffix = val[strlen(val) - 1];
		switch (suffix) {
			case 'k':
				*v *= 1000;
				break;
			case 'K':
				*v <<= 10;
				break;
			case 'm':
				*v *= 1000000ll;
				break;
			case 'M':
				*v <<= 20;
				break;
			default:
				if (suffix < '0' || suffix > '9')
					return POM_ERR;
		}

		return POM_OK;
	}

	return POM_ERR;

};

int ptype_print_uint32(struct ptype *p, char *val, size_t size) {

	uint32_t *v = p->value;

	switch (p->print_mode) {
		case PTYPE_UINT32_PRINT_HEX:
			return snprintf(val, size, "0x%X", *v);
		case PTYPE_UINT32_PRINT_HUMAN: {
			uint32_t value = *v;
			if (value > 99999) {
				value = (value + 500) / 1000;
				if (value > 9999) {
					value = (value + 500) / 1000;
					return snprintf(val, size, "%um", value);
				} else
					return snprintf(val, size, "%uk", value);
			} else
				return snprintf(val, size, "%u", value);
			break;
		}
		case PTYPE_UINT32_PRINT_HUMAN_1024: {
			uint32_t value = *v;
			if (value > 99999) {
				value = (value + 512) / 1024;
				if (value > 9999) {
					value = (value + 512) / 1024;
					return snprintf(val, size, "%uM", value);
				} else
					return snprintf(val, size, "%uK", value);
			} else
				return snprintf(val, size, "%u", value);
			break;
		}
		default:
		case PTYPE_UINT32_PRINT_DECIMAL:
			return snprintf(val, size, "%u", *v);
	}

	return 0;

}

int ptype_compare_uint32(int op, void *val_a, void* val_b) {

	uint32_t *a = val_a;
	uint32_t *b = val_b;

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

int ptype_serialize_uint32(struct ptype *p, char *val, size_t size) {

	uint32_t *v = p->value;
	return snprintf(val, size, "%u", *v);
}

int ptype_copy_uint32(struct ptype *dst, struct ptype *src) {

	*((uint32_t*)dst->value) = *((uint32_t*)src->value);
	return POM_OK;
}
