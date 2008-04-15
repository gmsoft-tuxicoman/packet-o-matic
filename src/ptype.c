/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2008 Guy Martin <gmsoft@tuxicoman.be>
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

int ptype_init() {

	int i;

	for (i = 0; i < MAX_PTYPE; i ++) {
		ptypes[i] = NULL;
	}

	return POM_OK;

}


int ptype_register(const char *ptype_name) {

	int i;

	
	for (i = 0; i < MAX_PTYPE; i++) {
		if (ptypes[i] != NULL) {
			if (strcmp(ptypes[i]->name, ptype_name) == 0) {
				return i;
			}
		} else {
			int (*register_my_ptype) (struct ptype_reg *);

			void *handle = NULL;
			register_my_ptype = lib_get_register_func("ptype", ptype_name, &handle);

			if (!register_my_ptype) {
				return POM_ERR;
			}

			struct ptype_reg *my_ptype = malloc(sizeof(struct ptype_reg));
			memset(my_ptype, 0, sizeof(struct ptype_reg));

			
			if ((*register_my_ptype) (my_ptype) != POM_OK) {
				pom_log(POM_LOG_ERR "Error while loading ptype %s. could not register ptype !\r\n", ptype_name);
				return POM_ERR;
			}


			ptypes[i] = my_ptype;
			ptypes[i]->name = malloc(strlen(ptype_name) + 1);
			strcpy(ptypes[i]->name, ptype_name);
			ptypes[i]->dl_handle = handle;

			pom_log(POM_LOG_DEBUG "Ptype %s registered\r\n", ptype_name);
			
			return i;
		}
	}

	return POM_ERR;

}


struct ptype* ptype_alloc(const char* type, char* unit) {

	int idx = ptype_register(type);

	if (idx == POM_ERR) {
		pom_log(POM_LOG_ERR "Error, could not allocate ptype of type %s\r\n", type);
		return NULL;
	}
	
	struct ptype *ret = malloc(sizeof(struct ptype));
	memset(ret, 0, sizeof(struct ptype));
	ret->type = idx;
	if (ptypes[idx]->alloc)
		ptypes[idx]->alloc(ret);

	if (unit)
		strncpy(ret->unit, unit, PTYPE_MAX_UNIT);

	ptypes[idx]->refcount++;

	return ret;
}

struct ptype* ptype_alloc_from(struct ptype *pt) {

	if (!ptypes[pt->type])
		return NULL;

	struct ptype *ret = malloc(sizeof(struct ptype));
	memset(ret, 0, sizeof(struct ptype));
	ret->type = pt->type;
	if (ptypes[ret->type]) {
		ptypes[pt->type]->alloc(ret);
		ptypes[pt->type]->copy(ret, pt);
	}


	if (pt->unit)
		strncpy(ret->unit, pt->unit, PTYPE_MAX_UNIT);

	ret->print_mode = pt->print_mode;

	ptypes[pt->type]->refcount++;

	return ret;

}

int ptype_parse_val(struct ptype *pt, char *val) {

	return ptypes[pt->type]->parse_val(pt, val);
}

int ptype_print_val(struct ptype *pt, char *val, size_t size) {

	return ptypes[pt->type]->print_val(pt, val, size);
}

int ptype_get_op(struct ptype *pt, char *op) {

	int o = 0;

	if (!strcmp(op, "eq") || !strcmp(op, "==") || !strcmp(op, "equals"))
		o = PTYPE_OP_EQUALS;
	else if (!strcmp(op, "gt") || !strcmp(op, ">")) 
		o = PTYPE_OP_GT;
	else if (!strcmp(op, "ge") || !strcmp(op, ">=")) 
		o = PTYPE_OP_GE;
	else if (!strcmp(op, "lt") || !strcmp(op, "<")) 
		o = PTYPE_OP_LT;
	else if (!strcmp(op, "le") || !strcmp(op, "<=")) 
		o = PTYPE_OP_LE;

	if (ptypes[pt->type]->ops & o)
		return o;

	pom_log(POM_LOG_ERR "Invalid operation %s for ptype %s\r\n", op, ptypes[pt->type]->name);
	return POM_ERR;
}

char *ptype_get_op_sign(int op) {
	switch (op) {
		case PTYPE_OP_EQUALS:
			return "==";
		case PTYPE_OP_GT:
			return ">";
		case PTYPE_OP_GE:
			return ">=";
		case PTYPE_OP_LT:
			return "<";
		case PTYPE_OP_LE:
			return "<=";

	}
	return NULL;
}

char *ptype_get_op_name(int op) {
	switch (op) {
		case PTYPE_OP_EQUALS:
			return "eq";
		case PTYPE_OP_GT:
			return "gt";
		case PTYPE_OP_GE:
			return "ge";
		case PTYPE_OP_LT:
			return "lt";
		case PTYPE_OP_LE:
			return "le";

	}
	return NULL;
}

int ptype_compare_val(int op, struct ptype *a, struct ptype *b) {
	
	if (a->type != b->type) {
		pom_log(POM_LOG_ERR "Cannot compare ptypes, type differs. What about you try not to compare pears with apples ...\r\n");
		return 0; // false
	}

	if (!(ptypes[a->type]->ops & op))
		pom_log(POM_LOG_ERR "Invalid operation %s for ptype %s\r\n", ptype_get_op_sign(op), ptypes[a->type]->name);

	return (*ptypes[a->type]->compare_val) (op, a->value, b->value);

}

int ptype_serialize(struct ptype *pt, char *val, size_t size) {

	return ptypes[pt->type]->serialize(pt, val, size);
}

int ptype_unserialize(struct ptype *pt, char *val) {

	return ptypes[pt->type]->unserialize(pt, val);
}

int ptype_copy(struct ptype *dst, struct ptype *src) {

	if (dst->type != src->type) {
		pom_log(POM_LOG_ERR "Error, trying to copy pytes of different type\r\n");
		return POM_ERR;
	}

	return ptypes[src->type]->copy(dst, src);
}


int ptype_cleanup(struct ptype* p) {

	if (!p)
		return POM_ERR;

	if (ptypes[p->type] && ptypes[p->type]->cleanup)
		ptypes[p->type]->cleanup(p);
	ptypes[p->type]->refcount--;
	free(p);

	return POM_OK;
}

int ptype_get_type(char* ptype_name) {
	
	int i;
	for (i = 0; i < MAX_PTYPE; i++) {
		if (ptypes[i] && strcmp(ptypes[i]->name, ptype_name) == 0)
			return i;
	}

	return POM_ERR;
}

int ptype_unregister(int ptype_type) {

	if (ptypes[ptype_type]) {
		if (ptypes[ptype_type]->refcount) {
			pom_log(POM_LOG_WARN "Warning, reference count not 0 for ptype %s\r\n", ptypes[ptype_type]->name);
			return POM_ERR;
		}
		dlclose(ptypes[ptype_type]->dl_handle);
		free(ptypes[ptype_type]->name);
		free(ptypes[ptype_type]);
		ptypes[ptype_type] = NULL;
	}

	return POM_OK;

}

int ptype_unregister_all() {

	int i;
	int result = POM_OK;
	for (i = 0; i < MAX_PTYPE; i++) {
		if (ptypes[i] && ptype_unregister(i) == POM_ERR);
			result = POM_ERR;
	}

	return result;

}
