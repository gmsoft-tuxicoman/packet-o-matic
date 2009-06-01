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


#ifndef __EXPECTATION_H__
#define __EXPECTATION_H__

#include "common.h"
#include "ptype.h"

#define EXPT_OP_IGNORE PTYPE_OP_RSVD

#define EXPT_DIR_FWD 1
#define EXPT_DIR_REV 2
#define EXPT_DIR_BOTH 3



struct expectation_field {
	
	int field_id; ///< id corresponding the the field id of the match
	char *name; ///< pointer to name in struct match_field_reg
	struct ptype* value;
	int op;	
	struct expectation_field *rev; ///< point to the reverse direction field if not NULL
	struct expectation_field *next;
};

struct expectation_node {

	int layer;
	struct expectation_field *fields;

	struct expectation_node *next; // used by targets to make a list of expectation they own

};

struct expectation_list {

	struct expectation_node *n;
	struct conntrack_entry *parent_ce;
	struct target *t;
	struct timer *expiry;
	void *target_priv;
	int (*target_priv_cleanup_handler) (struct target *t, struct conntrack_entry *ce, void *priv);
	int flags;

	struct expectation_list *next;
	struct expectation_list *prev;

};


int expectation_init();
struct expectation_list *expectation_alloc(struct target *t, struct conntrack_entry *ce, struct input *i, int direction);
struct expectation_node *expectation_add_layer(struct expectation_list *expt, int match_type);
int expectation_layer_set_field(struct expectation_node *n, char *fld_name, char *fld_value, int op);
struct expectation_list *expectation_alloc_from(struct frame *f, struct target *t, struct conntrack_entry *ce, int direction);
int expectation_set_target_priv(struct expectation_list *l, void *target_priv, int (*cleanup_handler) (struct target *t, struct conntrack_entry *ce, void *priv));
int expectation_add(struct expectation_list *l, unsigned int expiry);
int expectation_process (struct frame *f);
int expectation_cleanup_ce(struct target *t, struct conntrack_entry *ce);
int expectation_cleanup(struct expectation_list *l);
int expectation_cleanup_all();
int expectation_do_timer(void *priv);

#endif
