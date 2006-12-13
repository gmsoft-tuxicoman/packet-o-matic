/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

#include "common.h"
#include "timers.h"

#include <linux/jhash.h>

#define CT_DIR_NONE 0
#define CT_DIR_FWD 1
#define CT_DIR_REV 2
#define CT_DIR_BOTH 3

struct conntrack_entry {

	__u32 full_hash;
	struct conntrack_privs *match_privs;
	struct conntrack_privs *target_privs;

};

struct conntrack_list {

	__u32 hash;
	struct conntrack_entry *ce;
	struct conntrack_list *next;
	struct conntrack_list *rev;

};

struct conntrack_reg {

	void *dl_handle;
	unsigned int flags;
	__u32 (*get_hash) (void* frame, unsigned int start, unsigned int flags);
	int (*doublecheck) (void *frame, unsigned int start, void *priv, unsigned int flags);
	void* (*alloc_match_priv) (void *frame, unsigned int start, struct conntrack_entry *ce);
	int (*cleanup_match_priv) (void *priv);
	int (*conntrack_do_timeouts) (int (*conntrack_close_connection)(struct conntrack_entry *ce));


};

struct conntrack_functions {
	struct timer* (*alloc_timer) (struct conntrack_entry *);
	int (*cleanup_timer) (struct timer *t);
	int (*queue_timer) (struct timer *t, unsigned int expiry);
	int (*dequeue_timer) (struct timer *t);
//	int (*close_connection) (struct conntrack_entry *ce);


};

struct conntrack_privs {

	struct conntrack_privs *next;
	int priv_type;
	void *priv;
	unsigned int flags; // To store direction info

};

int conntrack_init();
int conntrack_register(const char *name);
int conntrack_add_target_priv(struct target*, void* priv, struct conntrack_entry *ce, unsigned int flags);
void *conntrack_get_target_priv(struct target*, struct conntrack_entry *ce);
__u32 conntrack_hash(struct rule_node *n, void *frame, unsigned int flags);
struct conntrack_entry *conntrack_find(struct conntrack_list *cl, struct rule_node *n, void *frame, unsigned int flags);
struct conntrack_entry *conntrack_get_entry(struct rule_node *n, void *frame);
struct conntrack_entry *conntrack_create_entry(struct rule_node *n, void *frame, __u32 hash, __u32 hash_rev);
int conntrack_do_timer(void * ce);
struct timer *conntrack_timer_alloc(struct conntrack_entry *ce);
int conntrack_cleanup();
int conntrack_unregister_all();


#endif
