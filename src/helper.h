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


#ifndef __HELPER_H__
#define __HELPER_H__

#include "common.h"
#include "rules.h"

struct helper_reg {

	void *dl_handle;
	int (*need_help) (void *frame, struct layer *l);
	int (*cleanup) (void);


};

struct helper_functions {
	struct timer* (*alloc_timer) (void *priv, int (*handler) (void *));
	int (*cleanup_timer) (struct timer *t);
	int (*queue_timer) (struct timer *t, unsigned int expiry);
	int (*dequeue_timer) (struct timer *t);
	int (*process_packet) (void *frame, unsigned int len, int first_layer);

};


int helper_init();
int helper_register(const char *name);
int helper_need_help(void *frame, struct layer *l);
int helper_process_packet(void *frame, unsigned int len, int first_layer);
int helper_set_feedback_rules(struct rule_list *rules);
int helper_unregister_all();
int helper_cleanup();


#endif
