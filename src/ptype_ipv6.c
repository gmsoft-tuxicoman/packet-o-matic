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
	
	return P_OK;

}

int ptype_alloc_ipv6(struct ptype* p) {

	p->value = malloc(sizeof(struct ptype_ipv6_val));
	struct ptype_ipv6_val *v = p->value;
	bzero(v, sizeof(struct ptype_ipv6_val));

	return P_OK;

}


int ptype_cleanup_ipv6(struct ptype *p) {

	free(p->value);
	return P_OK;
}


int ptype_parse_ipv6(struct ptype *p, char *val) {

	// TODO : HANDLE MASK

	struct ptype_ipv6_val *v = p->value;
	if (inet_pton(AF_INET6, val, &v->addr) <= 0)
		return P_ERR;

	return P_OK;

}

int ptype_print_ipv6(struct ptype *p, char *val, size_t size) {

	// TODO : HANDLE MASK

	struct ptype_ipv6_val *v = p->value;
	inet_ntop(AF_INET6, &v->addr, val, size);
	return strlen(val);
}

int ptype_compare_ipv6(int op, void *val_a, void *val_b) {

	// TODO : HANDLE MASK

	struct ptype_ipv6_val *a = val_a;
	struct ptype_ipv6_val *b = val_b;
	
	
	switch (op) {
		case PTYPE_OP_EQUALS:
			return (a->addr.s6_addr32[0] == b->addr.s6_addr32[0]
				&& a->addr.s6_addr32[1] == b->addr.s6_addr32[1]
				&& a->addr.s6_addr32[2] == b->addr.s6_addr32[2]
				&& a->addr.s6_addr32[3] == b->addr.s6_addr32[3]);
		default:
			dprint("Unkown operation %c\n", op);

	}

	return 0;
}
