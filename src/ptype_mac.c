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



#include "ptype_mac.h"


int ptype_register_mac(struct ptype_reg *r) {

	r->alloc = ptype_alloc_mac;
	r->cleanup = ptype_cleanup_mac;
	r->parse_val = ptype_parse_mac;
	r->print_val = ptype_print_mac;
	r->compare_val = ptype_compare_mac;
	
	r->ops = PTYPE_OP_EQUALS;
	
	return POM_OK;

}

int ptype_alloc_mac(struct ptype* p) {

	p->value = malloc(sizeof(struct ptype_mac_val));
	struct ptype_mac_val *v = p->value;
	bzero(v->addr, sizeof(v->addr));
	memset(v->mask, 0xff, sizeof(v->mask));

	return POM_OK;

}


int ptype_cleanup_mac(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_parse_mac(struct ptype *p, char *val) {

	// TODO : HANDLE MASK

	struct ptype_mac_val *v = p->value;

	if (sscanf(val, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", v->addr, v->addr + 1, v->addr + 2, v->addr + 3, v->addr + 4, v->addr + 5) == 6) {
		memset(v->mask, 0xff, sizeof(v->mask));
		return POM_OK;
	}

	return POM_ERR;

}

int ptype_print_mac(struct ptype *p, char *val, size_t size) {

	// TODO : HANDLE MASK

	struct ptype_mac_val *v = p->value;

	return snprintf(val, size, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
		v->addr[0],
		v->addr[1],
		v->addr[2],
		v->addr[3],
		v->addr[4],
		v->addr[5]);

}

int ptype_compare_mac(int op, void *val_a, void *val_b) {

	struct ptype_mac_val *a = val_a;
	struct ptype_mac_val *b = val_b;

	if(op == PTYPE_OP_EQUALS)
		return (memcmp(a->addr, b->addr, sizeof(a->addr)) == 0);

	return 0;
}
