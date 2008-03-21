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

#ifndef __PTYPE_H__
#define __PTYPE_H__

#include <unistd.h>

#define MAX_PTYPE 256

#define PTYPE_OP_EQUALS	0x01
#define PTYPE_OP_GT	0x02
#define PTYPE_OP_GE	0x04
#define PTYPE_OP_LT	0x08
#define PTYPE_OP_LE	0x10

#define PTYPE_OP_ALL	0x1f

#define PTYPE_MAX_UNIT 15


struct ptype {
	int type;
	char unit[PTYPE_MAX_UNIT + 1];
	void *value;
	unsigned int print_mode;
};

struct ptype_reg {

	char *name;
	int ops; ///< operation handled by this ptype
	void *dl_handle; ///< handle of the library
	unsigned int refcount;
	int (*alloc) (struct ptype*);
	int (*cleanup) (struct ptype*);

	int (*parse_val) (struct ptype *pt, char *val);
	int (*print_val) (struct ptype *pt, char *val, size_t size);

	int (*compare_val) (int op, void* val_a, void* val_b);

	int (*serialize) (struct ptype *pt, char *val, size_t size);
	int (*unserialize) (struct ptype *pt, char *val);

};

struct ptype_reg *ptypes[MAX_PTYPE];

int ptype_init(void);
int ptype_register(const char *ptype_name);
struct ptype* ptype_alloc(const char* type, char* unit);
struct ptype* ptype_alloc_from(struct ptype *pt);
int ptype_parse_val(struct ptype *pt, char *val);
int ptype_print_val(struct ptype *pt, char *val, size_t size);
int ptype_get_type(char* ptype_name);
int ptype_get_op(struct ptype *pt, char *op);
char *ptype_get_op_name(int op);
char *ptype_get_op_sign(int op);
int ptype_compare_val(int op, struct ptype *a, struct ptype *b);
int ptype_serialize(struct ptype *pt, char *val, size_t size);
int ptype_unserialize(struct ptype *pt, char *val);
int ptype_cleanup_module(struct ptype* p);
int ptype_unregister_all(void);

#endif
