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



#include "ptype_timestamp.h"


int ptype_register_timestamp(struct ptype_reg *r) {

	r->alloc = ptype_alloc_timestamp;
	r->cleanup = ptype_cleanup_timestamp;
	r->print_val = ptype_print_timestamp;
	r->compare_val = ptype_compare_timestamp;
	
	r->serialize = ptype_serialize_timestamp;
	r->unserialize = ptype_unserialize_timestamp;

	r->copy = ptype_copy_timestamp;
	
	r->ops = PTYPE_OP_ALL;

	return POM_OK;

}

int ptype_alloc_timestamp(struct ptype *p) {

	p->value = malloc(sizeof(time_t));
	time_t *v = p->value;
	*v = 0;

	return POM_OK;

}


int ptype_cleanup_timestamp(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_print_timestamp(struct ptype *p, char *val, size_t size) {

	time_t *v = p->value;

	char *format = "%Y-%m-%d %H:%M:%S";
	struct tm tmp;
	localtime_r((time_t*)v, &tmp);
	char buff[4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1];
	memset(buff, 0, sizeof(buff));
	strftime(buff, sizeof(buff), format, &tmp);

	// We must return what would have been written
	size_t len = strlen(buff);
	if (len > size - 1) {
		strncpy(val, buff, size - 1);
		val[size] = 0;
	} else {
		strcpy(val, buff);
	}
	return len;

}

int ptype_compare_timestamp(int op, void *val_a, void* val_b) {

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

int ptype_serialize_timestamp(struct ptype *p, char *val, size_t size) {

	time_t *v = p->value;
	return snprintf(val, size, "%lli", (long long)*v);
}

int ptype_unserialize_timestamp(struct ptype *p, char *val) {

	time_t *v = p->value;
	unsigned long long uv;
	if (sscanf(val,"%llu", &uv) != 1)
		return POM_ERR;
	*v = uv;
	return POM_OK;
};

int ptype_copy_timestamp(struct ptype *dst, struct ptype *src) {

	*((time_t*)dst->value) = *((time_t*)src->value);
	return POM_OK;
}
