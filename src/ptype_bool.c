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



#include "ptype_bool.h"


int ptype_register_bool(struct ptype_reg *r) {

	r->alloc = ptype_alloc_bool;
	r->cleanup = ptype_cleanup_bool;
	r->parse_val = ptype_parse_bool;
	r->print_val = ptype_print_bool;
	r->compare_val = ptype_compare_bool;

	r->serialize = ptype_print_bool;
	r->unserialize = ptype_parse_bool;

	r->copy = ptype_copy_bool;
	
	r->ops = PTYPE_OP_ALL;

	return POM_OK;

}

int ptype_alloc_bool(struct ptype *p) {

	p->value = malloc(sizeof(int));
	int *v = p->value;
	*v = 0;

	return POM_OK;

}

int ptype_cleanup_bool(struct ptype *p) {

	free(p->value);
	return POM_OK;
}

int ptype_parse_bool(struct ptype *p, char *val) {

	int *v = p->value;

	if(!strcasecmp(val, "yes") ||
		!strcasecmp(val, "true") ||
		!strcasecmp(val, "on") ||
		!strcasecmp(val, "1"))
		*v = 1;
	else if(!strcasecmp(val, "no") ||
		!strcasecmp(val, "false") ||
		!strcasecmp(val, "off") ||
		!strcasecmp(val, "0"))
		*v = 0;
	else
		return POM_ERR;

	return POM_OK;

};

int ptype_print_bool(struct ptype *p, char *val, size_t size) {

	int *v = p->value;

	if (*v) {
		strncpy(val, "yes", size);
		return strlen("yes");
	}

	strncpy(val, "no", size);
	return strlen("no");

}

int ptype_compare_bool(int op, void *val_a, void* val_b) {

	int *a = val_a;
	int *b = val_b;

	if (op == PTYPE_OP_EQ)
		return *a == *b;

	return 0;
}

int ptype_copy_bool(struct ptype *dst, struct ptype *src) {

	*((int*)dst->value) = *((int*) src->value);
	return POM_OK;

}
