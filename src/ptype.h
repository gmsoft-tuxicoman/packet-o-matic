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


#include <unistd.h>

#define P_OK 0

#define P_ERR -1

struct ptype_predef_vals {

	char *value;
	struct ptype_predef_vals *next;

};

#define PTYPE_MAX_DESCR 254
#define PTYPE_MAX_UNIT 30


struct ptype {
	int type;
	char descr[PTYPE_MAX_DESCR + 1];
	char unit[PTYPE_MAX_UNIT + 1];
	struct ptype_predef_vals predefs;
	void *value;
};

struct ptype_reg {

	char *name;
	void *dl_handle; ///< handle of the library
	int (*alloc) (struct ptype*);
	int (*cleanup) (struct ptype*);

	int (*parse_val) (struct ptype *pt, char *val);
	int (*print_val) (struct ptype *pt, char *val, size_t size);

};

int ptype_init(void);
int ptype_register(const char *ptype_name);
struct ptype* ptype_alloc(const char* type, char *descr, char* unit);
int ptype_parse_val(struct ptype *pt, char *val);
int ptype_print_val(struct ptype *pt, char *val, size_t size);
int ptype_cleanup_module(struct ptype* p);
int ptype_unregister_all(void);


