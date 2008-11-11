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

#include "ptype_ipv4.h"


#include <sys/socket.h>

int ptype_register_ipv4(struct ptype_reg *r) {

	r->alloc = ptype_alloc_ipv4;
	r->cleanup = ptype_cleanup_ipv4;
	r->parse_val = ptype_parse_ipv4;
	r->print_val = ptype_print_ipv4;
	r->compare_val = ptype_compare_ipv4;

	r->serialize = ptype_print_ipv4;
	r->unserialize = ptype_parse_ipv4;

	r->copy = ptype_copy_ipv4;

	r->ops = PTYPE_OP_EQ;
	
	return POM_OK;

}

int ptype_alloc_ipv4(struct ptype *p) {

	p->value = malloc(sizeof(struct ptype_ipv4_val));
	struct ptype_ipv4_val *v = p->value;
	memset(v, 0, sizeof(struct ptype_ipv4_val));
	v->mask = 32;

	return POM_OK;

}


int ptype_cleanup_ipv4(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_parse_ipv4(struct ptype *p, char *val) {

	struct ptype_ipv4_val *v = p->value;

	
	// Let's see first if there is a /
	int i;
	for (i = 0; i < strlen(val); i++) {
		if (val[i] == '/') {
			char ip[INET_ADDRSTRLEN];
			memset(ip, 0, INET_ADDRSTRLEN);
			strncpy(ip, val, i);
			unsigned char mask;
			if (sscanf(val + i + 1, "%hhu", &mask) != 1)
				return POM_ERR;
			if (mask > 32)
				return POM_ERR;
			v->mask = mask;
			if (inet_pton(AF_INET, ip, &v->addr) <= 0)
				return POM_ERR;

			return POM_OK;
		}
	}

	// Looks like there are no /


	if (inet_pton(AF_INET, val, &v->addr) <= 0)
		return POM_ERR;
	v->mask = 32;

	return POM_OK;

}

int ptype_print_ipv4(struct ptype *p, char *val, size_t size) {

	struct ptype_ipv4_val *v = p->value;
	if (v->mask < 32)
		return snprintf(val, size, "%s/%hhu", inet_ntoa(v->addr), v->mask);

	return snprintf(val, size, "%s", inet_ntoa(v->addr));
}

int ptype_compare_ipv4(int op, void *val_a, void *val_b) {

	struct ptype_ipv4_val *a = val_a;
	struct ptype_ipv4_val *b = val_b;

	if (op != PTYPE_OP_EQ)
		return 0;

	
	uint32_t masked_addr_a, masked_addr_b;
	int mask = a->mask;
	if (b->mask < mask)
		mask = b->mask;
	masked_addr_a = ntohl(a->addr.s_addr);
	masked_addr_b = ntohl(b->addr.s_addr);
	masked_addr_a &= (0xffffffff << (32 - mask));
	masked_addr_b &= (0xffffffff << (32 - mask));
	return (masked_addr_a == masked_addr_b);

}

int ptype_copy_ipv4(struct ptype *dst, struct ptype *src) {

	struct ptype_ipv4_val *d = dst->value;
	struct ptype_ipv4_val *s = src->value;
	memcpy(d, s, sizeof(struct ptype_ipv4_val));

	return POM_OK;
}
