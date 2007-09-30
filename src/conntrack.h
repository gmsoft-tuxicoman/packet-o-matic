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

#include "rules.h"

#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

#include "common.h"
#include "timers.h"
#include "helper.h"

#include "jhash.h"

/// One way only conntrack.
/***
 * The conntrack modules should set their flags to CT_DIR_ONEWAY
 * if the conntrack cannot match a reverse direction. \br
 * When computing the hash, CT_DIR_ONEWAY must be used to match bothe the forward direction and the one way direction.
 **/
#define CT_DIR_ONEWAY 0

/// The forward direction.
/**
 * Used to compute the forward hash. This is the forward direction WITHOUT the one way direction.
 **/
#define CT_DIR_FWD 1

/// The reverse direction.
/**
 * Used to compute the reverse hash.
 * The conntrack modules with CT_DIR_ONEWAY will be ignored.
 **/
#define CT_DIR_REV 2

/// Both directions.
/**
 * The conntrack modules should set their flags to CT_DIR_BOTH if they can handle both directions.
 **/
#define CT_DIR_BOTH 3


/// This structure contains all that needs to be known about a connection.
struct conntrack_entry {

	uint32_t full_hash;
	struct conntrack_match_priv *match_privs;
	struct conntrack_helper_priv *helper_privs;
	struct conntrack_target_priv *target_privs;
	unsigned int direction;

};


/// Structure used to avoid collisions if two connections have the same hash
struct conntrack_list {

	uint32_t hash;
	struct conntrack_entry *ce;
	struct conntrack_list *next;
	struct conntrack_list *rev;

};

struct conntrack_reg {

	void *dl_handle;
	unsigned int flags;
	uint32_t (*get_hash) (struct frame *f, unsigned int start, unsigned int flags);
	int (*doublecheck) (struct frame *f, unsigned int start, void *priv, unsigned int flags);
	void* (*alloc_match_priv) (struct frame *f, unsigned int start, struct conntrack_entry *ce);
	int (*cleanup_match_priv) (void *priv);
	int (*conntrack_do_timeouts) (int (*conntrack_close_connection)(struct conntrack_entry *ce));


};

struct conntrack_functions {
	struct timer* (*alloc_timer) (struct conntrack_entry *ce, struct input *i);
	int (*cleanup_timer) (struct timer *t);
	int (*queue_timer) (struct timer *t, unsigned int expiry);
	int (*dequeue_timer) (struct timer *t);


};


/// Structure which hold usefull data to identify the connection
struct conntrack_match_priv {

	struct conntrack_match_priv *next;
	unsigned int priv_type; ///< Type of match
	void *priv; ///< Private data of the match


};

/// Structure which hold private data for a target
struct conntrack_target_priv {

	struct conntrack_target_priv *next; ///< Next private stuff in the list
	struct target *t;
	void *priv; ///< The private data itself
	int (*cleanup_handler) (struct conntrack_entry *ce, void *priv); ///< Handler used to cleanup the conntrack priv

};

struct conntrack_helper_priv {

	struct conntrack_helper_priv *next; ///< Next private stuff in the list
	unsigned int type; ///< Type of helper
	void *priv; ///< The private data itself
	int (*flush_buffer) (struct conntrack_entry *ce, void *priv); ///< Handler used to flush the remaining packets in the helper if needed
	int (*cleanup_handler) (struct conntrack_entry *ce, void *priv); ///< Handler used to cleanup the conntrack priv

};
int conntrack_init();
int conntrack_register(const char *name);
int conntrack_add_target_priv(void *priv, struct target *t,  struct conntrack_entry *ce, int (*cleanup_handler) (struct conntrack_entry *ce, void *priv));
int conntrack_add_helper_priv(void *priv, int type, struct conntrack_entry *ce, int (*flush_buffer) (struct conntrack_entry *ce, void *priv), int (*cleanup_handler) (struct conntrack_entry *ce, void *priv));
void *conntrack_get_helper_priv(int type, struct conntrack_entry *ce);
int conntrack_remove_helper_priv(void *priv, struct conntrack_entry *ce);
void *conntrack_get_target_priv(struct target *t, struct conntrack_entry *ce);
uint32_t conntrack_hash(struct frame *f, unsigned int flags);
struct conntrack_entry *conntrack_find(struct conntrack_list *cl, struct frame *f, unsigned int flags);
int conntrack_get_entry(struct frame *f);
int conntrack_create_entry(struct frame *f);
int conntrack_cleanup_connection (struct conntrack_entry *ce);
int conntrack_do_timer(void * ce);
struct timer *conntrack_timer_alloc(struct conntrack_entry *ce, struct input *i);
int conntrack_close_connections(struct rule_list *r);
int conntrack_cleanup();
int conntrack_unregister_all();


#endif
