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



#include "ptype_bool.h"


int ptype_register_bool(struct ptype_reg *r) {

	r->parse_val = ptype_parse_bool;
	r->print_val = ptype_print_bool;
	r->compare_val = ptype_compare_bool;
	
	r->ops = PTYPE_OP_ALL;

	return P_OK;

}



int ptype_parse_bool(struct ptype *p, char *val) {


	if(!strcasecmp(val, "yes") ||
		!strcasecmp(val, "true") ||
		!strcasecmp(val, "on") ||
		!strcasecmp(val, "1"))
		p->value = (void*)1;
	else if(!strcasecmp(val, "no") ||
		!strcasecmp(val, "false") ||
		!strcasecmp(val, "off") ||
		!strcasecmp(val, "0"))
		p->value = (void*)0;
	else
		return P_ERR;

	return P_OK;

};

int ptype_print_bool(struct ptype *p, char *val, size_t size) {

	if ((int)p->value)
		strncpy(val, "yes", size);
	else
		strncpy(val, "no", size);
	return strlen(val);

}

int ptype_compare_bool(int op, void *val_a, void* val_b) {


	if (op == PTYPE_OP_EQUALS)
		return (int)val_a == (int)val_b;

	dprint("Unkown operation %c\n", op);
	return 0;
}
