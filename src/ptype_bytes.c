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



#include "ptype_bytes.h"


int ptype_register_bytes(struct ptype_reg *r) {

	r->alloc = ptype_alloc_bytes;
	r->cleanup = ptype_cleanup_bytes;
	r->parse_val = ptype_parse_bytes;
	r->print_val = ptype_print_bytes;
	r->compare_val = ptype_compare_bytes;

	r->serialize = ptype_print_bytes;
	r->unserialize = ptype_parse_bytes;

	r->copy = ptype_copy_bytes;
	
	r->ops = PTYPE_OP_EQUALS;
	
	return POM_OK;

}

int ptype_alloc_bytes(struct ptype *p) {

	p->value = malloc(sizeof(struct ptype_bytes_val));
	memset(p->value, 0, sizeof(struct ptype_bytes_val));

	return POM_OK;

}


int ptype_cleanup_bytes(struct ptype *p) {

	struct ptype_bytes_val *v = p->value;
	if (v->length > 0) {
		free(v->value);
		free(v->mask);
	}
	free(p->value);
	return POM_OK;
}


int ptype_parse_bytes_only(unsigned char **dest, size_t *len, char* string) {

	char *str, *token, *saveptr = NULL;
	*len = 0;
	*dest = NULL;

	for (str = string; ; str = NULL) {
		token = strtok_r(str, ":", &saveptr);
		if (token == NULL)
			break;
		*dest = realloc(*dest, *len + 1);
		if (strlen(token) == 0)
			*(*dest + *len) = 0;
		else {
			unsigned char tmp;
			if (sscanf(token, "%hhX", &tmp) != 1) {
				free(*dest);
				*dest = NULL;
				return POM_ERR;
			}
			*(*dest + *len) =  tmp;
		}
		(*len)++;
	}
	return POM_OK;
}


int ptype_parse_bytes(struct ptype *p, char *val) {

	struct ptype_bytes_val *v = p->value;

	char *slash = strchr(val, '/');

	unsigned char *new_value, *new_mask;
	size_t new_length = 0;

	if (slash) {
		*slash = 0;
		slash++;

		if (ptype_parse_bytes_only(&new_value, &new_length, val) == POM_ERR) {
			return POM_ERR;
		}

		size_t mask_len = 0;
		if (ptype_parse_bytes_only(&new_mask, &mask_len, slash) == POM_ERR) {
			free(new_value);
			return POM_ERR;
		}

		if (new_length != mask_len) {
			free(new_value);
			free(new_mask);
			return POM_ERR;
		}



	} else {
		if (ptype_parse_bytes_only(&new_value, &new_length, val) == POM_ERR)
			return POM_ERR;

		new_mask = malloc(new_length);
		memset(new_mask, 0xff, new_length);

	}
	
	v->length = new_length;
	if (v->value)
		free(v->value);
	v->value = new_value;
	if (v->mask)
		free(v->mask);
	v->mask = new_mask;

	return POM_OK;

}

int ptype_print_bytes(struct ptype *p, char *val, size_t size) {

	memset(val, 0, size);

	struct ptype_bytes_val *v = p->value;

	if (v->length == 0)
		return 0;

	int i, pos = 0;
	for (i = 0; i < v->length && pos < size; i++)
		pos += snprintf(val + pos, size - pos, "%02hhX:", v->value[i]);
	pos--;
	val[pos] = 0; // remove last :

	int printmask = 0;
	for (i = 0; i < v->length; i++)
		if (v->mask[i] != 0xff) {
			printmask = 1;
			break;
		}

	if (printmask) {
		if (pos >= size - 1)
			return pos;

		val[pos] = '/';
		pos++;

		for (i = 0; i < v->length && pos < size; i++)
			pos += snprintf(val + pos, size - pos, "%02hhX:", v->mask[i]);
			
		pos--;
		val[pos] = 0; // remove last :
	}

	return pos;

}

int ptype_compare_bytes(int op, void *val_a, void *val_b) {

	struct ptype_bytes_val *a = val_a;
	struct ptype_bytes_val *b = val_b;


	if (a->length != b->length)
		return 0;


	if (op == PTYPE_OP_EQUALS) {
		int i;
		for (i = 0; i < a->length; i++)
			if ((a->value[i] & a->mask[i]) != (b->value[i] & b->mask[i]))
				return 0;
	}

	return 1;
}

int ptype_copy_bytes(struct ptype *dst, struct ptype *src) {

	struct ptype_bytes_val *d = dst->value;
	struct ptype_bytes_val *s = src->value;

	d->length = s->length;
	d->value = realloc(d->value, d->length);
	d->mask = realloc(d->mask, d->length);
	if (d->length > 0) {
		memcpy(d->value, s->value, d->length);
		memcpy(d->mask, s->mask, d->length);
	} else {
		d->value = 0;
		d->mask = 0;
	}

	return POM_OK;
}

