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


#ifndef __TARGET_DISPLAY_H__
#define __TARGET_DISPLAY_H__

#include "modules_common.h"
#include "target.h"


struct target_conntrack_priv_display {

	struct conntrack_entry *ce;

	struct target_conntrack_priv_display *next;
	struct target_conntrack_priv_display *prev;

};

struct target_priv_display {

	struct ptype *skip;
	struct ptype *debug_level;
	struct ptype *print_hex;
	struct ptype *print_ascii;
	struct ptype *conntrack;

	struct target_conntrack_priv_display *ct_privs;

};

int target_register_display(struct target_reg *r, struct target_functions *tg_funcs);

int target_init_display(struct target *t);
int target_open_display(struct target *t);
int target_process_display(struct target *t, struct frame *f);
int target_close_display(struct target *t);
int target_cleanup_display(struct target *t);

int target_display_print_hex(void *frame, unsigned int start, unsigned int len, struct target_priv_display *p);
int target_display_print_ascii(void *frame, unsigned int start, unsigned int len, struct target_priv_display *p);

int target_close_connection_display(struct target *t, struct conntrack_entry *ce, void *conntrack_priv);


#endif
