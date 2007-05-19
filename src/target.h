/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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


struct target {
	int target_type;
	void *target_priv;
	char **params_value;

	int matched_conntrack;
	struct target *next;

};

struct target_reg {
	char *target_name;
	void *dl_handle;
	char **params_name;
	char **params_help;
	int (*init) (struct target*);
	int (*open) (struct target*);
	int (*process) (struct target*, struct layer *l, void*, unsigned int, struct conntrack_entry*);
	int (*close) (struct target *t);
	int (*cleanup) (struct target *t);
};
	

struct target_functions {

	int (*match_register) (const char *);
	struct conntrack_entry* (*conntrack_create_entry) (struct layer *l, void *frame);
	struct conntrack_entry* (*conntrack_get_entry) (struct layer *l, void* frame);
	int (*conntrack_add_priv) (void *priv, struct target *t,  struct conntrack_entry *ce, int (*cleanup_handler) (struct conntrack_entry *ce, void *priv));
	void *(*conntrack_get_priv) (struct target *t, struct conntrack_entry *ce);
	int (*layer_info_snprintf) (char *buff, unsigned int maxlen, struct layer_info *inf);
	char *(*match_get_name) (int match_type);

};

int target_init();
int target_register(const char *target_name);
struct target *target_alloc(int target_type);
int target_set_param(struct target *t, char *name, char* value);
int target_open(struct target *t);
int target_process(struct target *t, struct layer *l, unsigned char *buffer, unsigned int bufflen, struct conntrack_entry *ce);
int target_close(struct target *t);
int target_cleanup_t(struct target *t);
int target_unregister_all();
void target_print_help();
int target_cleanup();


#endif
