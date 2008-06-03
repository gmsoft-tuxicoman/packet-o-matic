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

#include <pthread.h>

static pthread_rwlock_t ptype_global_lock = PTHREAD_RWLOCK_INITIALIZER;


/**
 * @ingroup ptype_core
 */
int ptype_init() {

	int i;

	for (i = 0; i < MAX_PTYPE; i ++) {
		ptypes[i] = NULL;
	}

	return POM_OK;

}

/**
 * @ingroup ptype_api
 * @param ptype_name Name of the ptype to register
 * @return Ptype type or POM_ERR on failure.
 */
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

/**
 * @ingroup ptype_api
 * @param type Type of the ptype
 * @param unit Unit of the values store by this ptype, NULL if not applicable
 * @return Allocated struct ptype or NULL on error.
 */
struct ptype* ptype_alloc(const char* type, char* unit) {

	ptype_lock(1);

	int idx = ptype_register(type);

	if (idx == POM_ERR) {
		ptype_unlock();
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

	ptype_unlock();

	return ret;
}

/**
 * @ingroup ptype_api
 * @param pt Ptype to clone
 * @return A clone of the provided ptype or NULL on failure.
 */
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

/**
 * @ingroup ptype_core
 * @param pt Ptype to store value to
 * @param val String to parse
 * @return POM_OK on success, POM_ERR on failure.
 */
int ptype_parse_val(struct ptype *pt, char *val) {

	return ptypes[pt->type]->parse_val(pt, val);
}

/**
 * @ingroup ptype_core
 * @param pt Ptype which contains the value to print
 * @param val Preallocated buffer to store the value
 * @param size Size of the preallocated buffer
 * @return Number of bytes copied into the buffer.
 */
int ptype_print_val(struct ptype *pt, char *val, size_t size) {

	return ptypes[pt->type]->print_val(pt, val, size);
}

/**
 * @ingroup ptype_core
 * @param pt Ptype to get the operation from
 * @param op String representation of the operation
 * @return The operation indentifier or POM_ERR on error.
 */
int ptype_get_op(struct ptype *pt, char *op) {

	int o = 0;

	if (!strcmp(op, "eq") || !strcmp(op, "==") || !strcmp(op, "equals"))
		o = PTYPE_OP_EQ;
	else if (!strcmp(op, "gt") || !strcmp(op, ">")) 
		o = PTYPE_OP_GT;
	else if (!strcmp(op, "ge") || !strcmp(op, ">=")) 
		o = PTYPE_OP_GE;
	else if (!strcmp(op, "lt") || !strcmp(op, "<")) 
		o = PTYPE_OP_LT;
	else if (!strcmp(op, "le") || !strcmp(op, "<=")) 
		o = PTYPE_OP_LE;
	else if (!strcmp(op, "neq") || !strcmp(op, "!="))
		o = PTYPE_OP_NEQ;

	if (ptypes[pt->type]->ops & o)
		return o;

	pom_log(POM_LOG_ERR "Invalid operation %s for ptype %s\r\n", op, ptypes[pt->type]->name);
	return POM_ERR;
}

/**
 * @ingroup ptype_core
 * @param op Operation identifier
 * @return String representation of the operation or NULL on error.
 */
char *ptype_get_op_sign(int op) {
	switch (op) {
		case PTYPE_OP_EQ:
			return "==";
		case PTYPE_OP_GT:
			return ">";
		case PTYPE_OP_GE:
			return ">=";
		case PTYPE_OP_LT:
			return "<";
		case PTYPE_OP_LE:
			return "<=";
		case PTYPE_OP_NEQ:
			return "!=";

	}
	return NULL;
}

/**
 * @ingroup ptype_core
 * @param op Operation identifier
 * @return Alphanumeric string representation of the operation or NULL on error.
 */
char *ptype_get_op_name(int op) {
	switch (op) {
		case PTYPE_OP_EQ:
			return "eq";
		case PTYPE_OP_GT:
			return "gt";
		case PTYPE_OP_GE:
			return "ge";
		case PTYPE_OP_LT:
			return "lt";
		case PTYPE_OP_LE:
			return "le";
		case PTYPE_OP_NEQ:
			return "neq";

	}
	return NULL;
}

/**
 * @ingroup ptype_core
 * @param op Operation identifier
 * @param a First ptype
 * @param b Second ptype
 * @return Result of the comparaision (true or false).
 */
int ptype_compare_val(int op, struct ptype *a, struct ptype *b) {
	
	if (a->type != b->type) {
		pom_log(POM_LOG_ERR "Cannot compare ptypes, type differs. What about you try not to compare pears with apples ...\r\n");
		return 0; // false
	}

	if (!(ptypes[a->type]->ops & op))
		pom_log(POM_LOG_ERR "Invalid operation %s for ptype %s\r\n", ptype_get_op_sign(op), ptypes[a->type]->name);

	if (op == PTYPE_OP_NEQ)
		return !(*ptypes[a->type]->compare_val) (PTYPE_OP_EQ, a->value, b->value);
	return (*ptypes[a->type]->compare_val) (op, a->value, b->value);

}

/**
 * @ingroup ptype_core
 * @param pt Ptype to serialize
 * @param val Buffer to store the serialized value
 * @param size Size of the preallocated buffer
 * @return Number of bytes written to the buffer.
 */
int ptype_serialize(struct ptype *pt, char *val, size_t size) {

	return ptypes[pt->type]->serialize(pt, val, size);
}

/**
 * @ingroup ptype_core
 * @param pt Ptype to unserialize
 * @param val Serialized value
 * @return POM_OK on success, POM_ERR on failure.
 */
int ptype_unserialize(struct ptype *pt, char *val) {

	return ptypes[pt->type]->unserialize(pt, val);
}


/**
 * @ingroup ptype_core
 * @param dst Ptype to store value to
 * @param src Ptype to copy value from
 * @return POM_OK on success, POM_ERR on failure.
 */
int ptype_copy(struct ptype *dst, struct ptype *src) {

	if (dst->type != src->type) {
		pom_log(POM_LOG_ERR "Error, trying to copy pytes of different type\r\n");
		return POM_ERR;
	}

	return ptypes[src->type]->copy(dst, src);
}

/**
 * @ingroup ptype_api
 * @param p Ptype to cleanup
 * @return POM_OK on success, POM_ERR on failure.
 */
int ptype_cleanup(struct ptype* p) {

	if (!p)
		return POM_ERR;

	if (ptypes[p->type] && ptypes[p->type]->cleanup)
		ptypes[p->type]->cleanup(p);
	ptypes[p->type]->refcount--;
	free(p);

	return POM_OK;
}

/**
 * @ingroup ptype_api
 * @param ptype_name Name of the ptype
 * @return the Ptype type or POM_ERR on failure.
 */
int ptype_get_type(char* ptype_name) {
	
	int i;
	for (i = 0; i < MAX_PTYPE; i++) {
		if (ptypes[i] && strcmp(ptypes[i]->name, ptype_name) == 0)
			return i;
	}

	return POM_ERR;
}

/**
 * @ingroup ptype_core
 * @param type Type of the ptype
 * @return String representation of the type or NULL on failure.
 */

char * ptype_get_name(unsigned int type) {

	if (type > MAX_PTYPE)
		return NULL;

	if (ptypes[type])
		return ptypes[type]->name;

	return NULL;
}

/**
 * @ingroup ptype_core
 * @param ptype_type Type of the ptype
 * @return POM_OK on success, POM_ERR on failure.
 */
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

/**
 * @ingroup ptype_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int ptype_unregister_all() {

	int i;
	int result = POM_OK;
	for (i = 0; i < MAX_PTYPE; i++) {
		if (ptypes[i] && ptype_unregister(i) == POM_ERR);
			result = POM_ERR;
	}

	return result;

}

/**
 * @ingroup ptype_core
 * @param write Set to 1 if ptypes will be modified, 0 if not
 * @return POM_OK on success, POM_ERR on failure.
 */
int ptype_lock(int write) {

	int result = 0;
	if (write) {
		result = pthread_rwlock_wrlock(&ptype_global_lock);
	} else {
		result = pthread_rwlock_rdlock(&ptype_global_lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking the ptype lock\r\n");
		return POM_ERR;
	}

	return POM_OK;

}

/**
 * @ingroup ptype_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int ptype_unlock() {

	if (pthread_rwlock_unlock(&ptype_global_lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the ptype lock\r\n");
		return POM_ERR;
	}

	return POM_OK;

}

