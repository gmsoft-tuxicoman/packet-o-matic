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

#include <linux/jhash.h>

struct conntrack_timer {

	time_t expires;
	struct conntrack_entry *ce;
	struct conntrack_timer *next;
	struct conntrack_timer *prev;

};

struct conntrack_timer_queue {

	unsigned int expiry;
	struct conntrack_timer_queue *next;
	struct conntrack_timer_queue *prev;
	struct conntrack_timer *head;
	struct conntrack_timer *tail;

};

struct conntrack_entry {

	__u32 hash;
	struct conntrack_entry *next;
	struct conntrack_privs *match_privs;
	struct conntrack_privs *target_privs;

};

struct conntrack_reg {

	void *dl_handle;
	__u32 (*get_hash) (void* frame, unsigned int);
	int (*doublecheck) (void *frame, unsigned int start, void *priv, struct conntrack_entry *ce);
	void* (*alloc_match_priv) (void *frame, unsigned int start, struct conntrack_entry *ce);
	int (*cleanup_match_priv) (void *priv);
	int (*conntrack_do_timeouts) (int (*conntrack_close_connection)(struct conntrack_entry *ce));


};

struct conntrack_functions {
	struct conntrack_timer* (*alloc_timer) (struct conntrack_entry *);
	int (*cleanup_timer) (struct conntrack_timer *t);
	int (*queue_timer) (struct conntrack_timer *t, unsigned int expiry);
	int (*dequeue_timer) (struct conntrack_timer *t);
	int (*close_connection) (struct conntrack_entry *ce);


};

struct conntrack_privs {

	struct conntrack_privs *next;
	int priv_type;
	void *priv;

};

int conntrack_init();
int conntrack_register(const char *name);
int conntrack_add_target_priv(struct target*, void *priv, struct rule_node *n, void* frame);
void *conntrack_get_target_priv(struct target*, struct rule_node *n, void *frame);
__u32 conntrack_hash(struct rule_node *n, void *frame);
struct conntrack_entry *conntrack_get_entry(__u32 hash, struct rule_node *n, void *frame);
int conntrack_cleanup();
int conntrack_unregister_all();
int conntrack_do_timers();
struct conntrack_timer *conntrack_timer_alloc(struct conntrack_entry *ce);
int conntrack_timer_cleanup(struct conntrack_timer *t);
int conntrack_timer_queue(struct conntrack_timer *t, unsigned int expiry);
int conntrack_timer_dequeue(struct conntrack_timer *t);


#endif
