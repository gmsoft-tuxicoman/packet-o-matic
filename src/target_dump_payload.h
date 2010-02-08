/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2010 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __TARGET_DUMP_PAYLOAD_H__
#define __TARGET_DUMP_PAYLOAD_H__


#include "modules_common.h"
#include "rules.h"

struct target_conntrack_priv_dump_payload {

	int fd;

	struct conntrack_entry *ce;

	struct target_conntrack_priv_dump_payload *next;
	struct target_conntrack_priv_dump_payload *prev;

};

struct target_priv_dump_payload {

	struct ptype *prefix;
	struct ptype *markdir;
	struct target_conntrack_priv_dump_payload *ct_privs;

	struct perf_item *perf_tot_conn, *perf_cur_conn, *perf_tot_bytes;

};

int target_register_dump_payload(struct target_reg *r);

static int target_init_dump_payload(struct target *t);
static int target_process_dump_payload(struct target *t, struct frame *f);
static int target_close_connection_dump_payload(struct target *t, struct conntrack_entry* ce, void *conntrack_priv);
static int target_close_dump_payload(struct target *t);
static int target_cleanup_dump_payload(struct target *t);

#endif
