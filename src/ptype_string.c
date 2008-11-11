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



#include "ptype_string.h"


int ptype_register_string(struct ptype_reg *r) {

	r->cleanup = ptype_cleanup_string;
	r->parse_val = ptype_parse_string;
	r->print_val = ptype_print_string;
	r->compare_val = ptype_compare_string;

	r->serialize = ptype_print_string;
	r->unserialize = ptype_parse_string;

	r->copy = ptype_copy_string;

	r->ops = PTYPE_OP_EQ;
	
	return POM_OK;

}


int ptype_cleanup_string(struct ptype *p) {

	if (p->value)
		free(p->value);
	return POM_OK;
}


int ptype_parse_string(struct ptype *p, char *val) {

	char *str = realloc(p->value, strlen(val) + 1);
	strcpy(str, val);
	p->value = str;

	return POM_OK;

}

int ptype_print_string(struct ptype *p, char *val, size_t size) {

	char *str = p->value;
	return snprintf(val, size, "%s", str);

}

int ptype_compare_string(int op, void *val_a, void *val_b) {

	char *a = val_a;
	char *b = val_b;

	if (op == PTYPE_OP_EQ)
		return !strcmp(a, b);
	
	return 0;
}

int ptype_copy_string(struct ptype *dst, struct ptype *src) {

	if (!src->value) {
		if (dst->value) {
			free(dst->value);
			dst->value = 0;
		}
		return POM_OK;
	}

	dst->value = realloc(dst->value, strlen(src->value) + 1);
	strcpy(dst->value, src->value);

	return POM_OK;
}
