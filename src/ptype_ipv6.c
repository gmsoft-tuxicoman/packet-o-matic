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



#include "ptype_ipv6.h"


int ptype_register_ipv6(struct ptype_reg *r) {

	r->alloc = ptype_alloc_ipv6;
	r->cleanup = ptype_cleanup_ipv6;
	r->parse_val = ptype_parse_ipv6;
	r->print_val = ptype_print_ipv6;
	r->compare_val = ptype_compare_ipv6;
	
	r->ops = PTYPE_OP_EQUALS;
	
	return POM_OK;

}

int ptype_alloc_ipv6(struct ptype *p) {

	p->value = malloc(sizeof(struct ptype_ipv6_val));
	struct ptype_ipv6_val *v = p->value;
	bzero(v, sizeof(struct ptype_ipv6_val));
	v->mask = 128;

	return POM_OK;

}


int ptype_cleanup_ipv6(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_parse_ipv6(struct ptype *p, char *val) {

	struct ptype_ipv6_val *v = p->value;

	// Let's see first if there is a /
	int i;
	for (i = 0; i < strlen(val); i++) {
		if (val[i] == '/') {
			char ip[INET6_ADDRSTRLEN];
			bzero(ip, INET6_ADDRSTRLEN);
			strncpy(ip, val, i);
			unsigned char mask;
			if (sscanf(val + i + 1, "%hhu", &mask) != 1)
				return POM_ERR;
			if (mask > 128)
				return POM_ERR;
			v->mask = mask;
			if (inet_pton(AF_INET6, ip, &v->addr) <= 0)
				return POM_ERR;

			return POM_OK;
		}
	}

	// Looks like there are no /


	if (inet_pton(AF_INET6, val, &v->addr) <= 0)
		return POM_ERR;
	v->mask = 128;

	return POM_OK;

}

int ptype_print_ipv6(struct ptype *p, char *val, size_t size) {

	struct ptype_ipv6_val *v = p->value;
	inet_ntop(AF_INET6, &v->addr, val, size);
	size -= strlen(val);
	if (v->mask < 128 && size >= 4) {
		strcat(val, "/");
		sprintf(val + strlen(val), "%hhu", v->mask);
	}
	return strlen(val);
}

int ptype_compare_ipv6(int op, void *val_a, void *val_b) {

	struct ptype_ipv6_val *a = val_a;
	struct ptype_ipv6_val *b = val_b;

	if (op != PTYPE_OP_EQUALS)
		return 0;

	int minmask = a->mask;
	if (b->mask < minmask)
		minmask = b->mask;
	
	uint32_t mask[4];
	if (minmask <= 32) {
		mask[0] = (0xffffffff << (32 - minmask));
		mask[1] = 0;
		mask[2] = 0;
		mask[3] = 0;
	} else if (minmask <= 64) {
		mask[0] = 0xffffffff;
		mask[1] = (0xffffffff << (64 - minmask));
		mask[2] = 0;
		mask[3] = 0;
	} else if (minmask <= 96) {
		mask[0] = 0xffffffff;
		mask[1] = 0xffffffff;
		mask[2] = (0xffffffff << (96 - minmask));
		mask[3] = 0;
	} else {
		mask[0] = 0xffffffff;
		mask[1] = 0xffffffff;
		mask[2] = 0xffffffff;
		mask[3] = (0xffffffff << (128 - minmask));
	}
	
	return ((a->addr.s6_addr32[0] & mask[0]) == (b->addr.s6_addr32[0] & mask[0])
		&& (a->addr.s6_addr32[1] & mask[1]) == (b->addr.s6_addr32[1] & mask[1])
		&& (a->addr.s6_addr32[2] & mask[2]) == (b->addr.s6_addr32[2] & mask[2])
		&& (a->addr.s6_addr32[3] & mask[3]) == (b->addr.s6_addr32[3] & mask[3]));
}
