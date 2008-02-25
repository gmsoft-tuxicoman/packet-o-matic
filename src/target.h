/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __TARGET_H__
#define __TARGET_H__

#include "conntrack.h"
#include "match.h"
#include "ptype.h"


struct target_param_reg {

	char *name;
	char *defval;
	char *descr;
	struct target_param_reg *next;

};

struct target_param {

	struct target_param_reg *type;
	struct ptype *value;
	struct target_param *next;

};

struct target_mode {

	char *name;
	char *descr;
	struct target_param_reg *params;
	struct target_mode *next;

};

struct target_reg {
	char *target_name;
	int type;
	void *dl_handle;
	struct target_mode *modes;
	int (*init) (struct target*);
	int (*open) (struct target*);
	int (*process) (struct target*, struct frame *f);
	int (*close) (struct target *t);
	int (*cleanup) (struct target *t);
};

struct target {
	int type;
	void *target_priv;
	struct target_param *params;
	struct target_mode *mode;
	int matched_conntrack;
	int started;

	struct ptype* pkt_cnt;
	struct ptype* byte_cnt;

	struct target *next;
	struct target *prev;
};


struct target_functions {

	void (*pom_log) (const char *format, ...);
	int (*match_register) (const char *);
	struct target_mode *(*register_mode) (int , const char *, const char *);
	int (*register_param) (struct target_mode *, char *, char *, char *);
	int (*register_param_value) (struct target *t, struct target_mode *mode, const char *name, struct ptype *value);
	struct ptype* (*ptype_alloc) (const char* , char*);
	int (*ptype_print_val) (struct ptype *pt, char *val, size_t size);
	int (*ptype_cleanup) (struct ptype*);
	int (*conntrack_create_entry) (struct frame *f);
	int (*conntrack_add_priv) (void *priv, struct target *t,  struct conntrack_entry *ce, int (*cleanup_handler) (struct target *t, struct conntrack_entry *ce, void *priv));
	void *(*conntrack_get_priv) (struct target *t, struct conntrack_entry *ce);
	int (*conntrack_remove_priv) (void *priv, struct conntrack_entry *ce);
	char *(*match_get_name) (int match_type);
	struct match_field_reg *(*match_get_field) (int match_type, int field_id);
	int (*file_open) (struct layer *l, char *filename, int flags, mode_t mode);
	int (*layer_field_parse) (struct layer *, char *expr, char *buff, size_t size);



};

int target_init();
int target_register(const char *target_name);
struct target_mode *target_register_mode(int target_type, const char *name, const char *descr);
int target_register_param(struct target_mode *mode, char *name, char *defval, char *descr);
int target_register_param_value(struct target *t, struct target_mode *mode, const char *name, struct ptype *value);
struct target *target_alloc(int target_type);
int target_set_mode(struct target *t, const char *mode_name);
struct ptype *target_get_param_value(struct target *t, const char *param);
char *target_get_name(int target_type);
int target_open(struct target *t);
int target_process(struct target *t, struct frame *f);
int target_close(struct target *t);
int target_cleanup_module(struct target *t);
int target_unregister(int target_type);
int target_unregister_all();
void target_print_help();
int target_cleanup();
int target_file_open(struct layer *l, char *filename, int flags, mode_t mode);

#endif
