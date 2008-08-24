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



#include "ptype_interval.h"


int ptype_register_interval(struct ptype_reg *r) {

	r->alloc = ptype_alloc_interval;
	r->cleanup = ptype_cleanup_interval;
	r->parse_val = ptype_parse_interval;
	r->print_val = ptype_print_interval;
	r->compare_val = ptype_compare_interval;
	
	r->serialize = ptype_serialize_interval;
	r->unserialize = ptype_parse_interval;

	r->copy = ptype_copy_interval;
	
	r->ops = PTYPE_OP_ALL;

	return POM_OK;

}

int ptype_alloc_interval(struct ptype *p) {

	p->value = malloc(sizeof(time_t));
	time_t *v = p->value;
	*v = 0;

	strcpy(p->unit, "seconds");

	return POM_OK;

}


int ptype_cleanup_interval(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_parse_interval(struct ptype *p, char *val) {


	unsigned long value;
	if (sscanf(val, "%lu", &value) == 1) {
		char suffix = val[strlen(val) - 1];
		switch (suffix) {
			case 's':
			case 'S':
				break;
			case 'm':
			case 'M':
				value *= 60;
				break;
			case 'h':
			case 'H':
				value *= 3600;
				break;
			case 'd':
			case 'D':
				value *= 86400;
				break;
			case 'w':
			case 'W':
				value *= 604800;
				break;
			default:
				if (suffix < '0' || suffix > '9')
					return POM_ERR;
		}

		time_t *v = p->value;
		*v = (time_t) value;

		return POM_OK;
	}

	return POM_ERR;

};

int ptype_print_interval(struct ptype *p, char *val, size_t size) {

	time_t *v = p->value;
	return snprintf(val, size, "%lu", *v);

}

int ptype_compare_interval(int op, void *val_a, void* val_b) {

	time_t *a = val_a;
	time_t *b = val_b;

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

int ptype_serialize_interval(struct ptype *p, char *val, size_t size) {

	time_t *v = p->value;
	return snprintf(val, size, "%lu", *v);
}

int ptype_copy_interval(struct ptype *dst, struct ptype *src) {

	*((time_t*)dst->value) = *((time_t*)src->value);
	return POM_OK;
}
