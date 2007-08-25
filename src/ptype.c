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

#include "common.h"
#include "ptype.h"

#define MAX_P 256

struct ptype_reg *ptypes[MAX_P];

int ptype_init() {

	int i;

	for (i = 0; i < MAX_P; i ++) {
		ptypes[i] = NULL;
	}

	return P_OK;

}


int ptype_register(const char *ptype_name) {

	int i;

	
	for (i = 0; i < MAX_P; i++) {
		if (ptypes[i] != NULL) {
			if (strcmp(ptypes[i]->name, ptype_name) == 0) {
				return i;
			}
		} else {
			int (*register_my_ptype) (struct ptype_reg *);

			void *handle = NULL;
			register_my_ptype = lib_get_register_func("ptype", ptype_name, &handle);

			if (!register_my_ptype) {
				return -1;
			}

			struct ptype_reg *my_ptype = malloc(sizeof(struct ptype_reg));
			bzero(my_ptype, sizeof(struct ptype_reg));

			
			if ((*register_my_ptype) (my_ptype) != P_OK) {
				dprint("Error while loading ptype %s. could not register ptype !\n", ptype_name);
				return -1;
			}


			ptypes[i] = my_ptype;
			ptypes[i]->name = malloc(strlen(ptype_name) + 1);
			strcpy(ptypes[i]->name, ptype_name);
			ptypes[i]->dl_handle = handle;

			dprint("Ptype %s registered\n", ptype_name);
			
			return i;
		}
	}

	return P_ERR;

}


struct ptype* ptype_alloc(const char* type, char *descr, char* unit) {

	int idx = ptype_register(type);

	if (idx == P_ERR) {
		dprint("Error, could not allocate ptype of type %s\n", type);
		return NULL;
	}
	
	struct ptype *ret = malloc(sizeof(struct ptype));
	bzero(ret, sizeof(struct ptype));
	ret->type = idx;
	ptypes[idx]->alloc(ret);

	strncpy(ret->descr, descr, PTYPE_MAX_DESCR);
	strncpy(ret->unit, unit, PTYPE_MAX_UNIT);

	return ret;
}

int ptype_parse_val(struct ptype *pt, char *val) {

	return ptypes[pt->type]->parse_val(pt, val);
}

int ptype_print_val(struct ptype *pt, char *val, size_t size) {

	return ptypes[pt->type]->print_val(pt, val, size);
}


int ptype_cleanup_module(struct ptype* p) {

	if (!p)
		return P_ERR;

	if (ptypes[p->type] && ptypes[p->type]->cleanup)
		ptypes[p->type]->cleanup(p);
	free(p);

	return P_OK;
}

int ptype_unregister_all() {

	int i;
	for (i = 0; i < MAX_P && ptypes[i]; i++) {
		free(ptypes[i]->name);
		free(ptypes[i]);
		ptypes[i] = NULL;
	}

	return P_OK;

}