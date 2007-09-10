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


#ifndef __HELPER_H__
#define __HELPER_H__


#include "common.h"
#include "rules.h"

/// Return value in case of error
#define H_ERR -1

/// Return value on success
#define H_OK 0

/// Return value if the packet needs to be processed by the helper
/// Returned by helper_need_help only
#define H_NEED_HELP 1

#define MAX_HELPER MAX_MATCH

/// Stores informations about a frame that needs to be processed
struct helper_frame {

	struct frame *f; ///< The frame
	struct helper_frame *next; ///< Next frame in the list

};

struct helper_param {

	char *name;
	char *defval;
	char *descr;
	struct ptype *value;
	struct helper_param *next;

};

struct helper_reg {

	int type; ///< unique id of the helper
	void *dl_handle;
	int (*need_help) (struct frame *f, unsigned int start, unsigned int len, struct layer *l);
	int (*flush_buffer) (void);
	int (*cleanup) (void);
	struct helper_param *params;


};

struct helper_functions {
	int (*register_param) (int helper_type, char *name, char *defval, struct ptype *value, char *descr);
	struct timer* (*alloc_timer) (void *priv, struct input *i, int (*handler) (void *));
	int (*cleanup_timer) (struct timer *t);
	int (*queue_timer) (struct timer *t, unsigned int expiry);
	int (*dequeue_timer) (struct timer *t);
	int (*queue_frame) (struct frame *f);
	int (*layer_info_snprintf) (char *buff, unsigned int maxlen, struct layer_info *inf);
	int (*conntrack_create_entry) (struct frame *f);
	int (*conntrack_get_entry) (struct frame *f);
	int (*conntrack_add_priv) (void *priv, int type, struct conntrack_entry *ce, int (*flush_buffer) (struct conntrack_entry *ce, void *priv), int (*cleanup_handler) (struct conntrack_entry *ce, void *priv));
	int (*conntrack_remove_priv) (void *priv, struct conntrack_entry *ce);
	void *(*conntrack_get_priv) (int type, struct conntrack_entry *ce);
	struct ptype* (*ptype_alloc) (const char* type, char* unit);
	int (*ptype_cleanup) (struct ptype* p);



};


int helper_init();
int helper_register(const char *name);
int helper_register_param(int helper_type, char *name, char *defval, struct ptype *value, char *descr);
struct helper_param* helper_get_param(int helper_type, char* param_name);
int helper_need_help(struct frame *f, unsigned int start, unsigned int len, struct layer *l);
int helper_queue_frame(struct frame *f);
int helper_flush_buffer(struct rule_list *list);
int helper_process_queue(struct rule_list *list);
int helper_unregister(int helper_type);
int helper_unregister_all();
int helper_cleanup();


#endif
