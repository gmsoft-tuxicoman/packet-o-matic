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


#ifndef __TARGET_RTP_H__
#define __TARGET_RTP_H__


#include "modules_common.h"
#include "rules.h"

struct au_hdr {

	char magic[4];
	uint32_t hdr_size;
	uint32_t data_size;
	uint32_t encoding;
	uint32_t sample_rate;
	uint32_t channels;


};

struct target_conntrack_priv_rtp {

	int fd;
	uint16_t last_seq;
	unsigned int total_size;
	unsigned int payload_type;

	struct conntrack_entry *ce;

	struct target_conntrack_priv_rtp *next;
	struct target_conntrack_priv_rtp *prev;

};

struct target_priv_rtp {

	struct ptype *prefix;

	struct target_conntrack_priv_rtp *ct_privs;

};

int target_register_rtp(struct target_reg *r, struct target_functions *tg_funcs);

int target_init_rtp(struct target *t);
int target_process_rtp(struct target *t, struct frame *f);
int target_close_connection_rtp(struct target *t, struct conntrack_entry *ce, void *conntrack_priv);
int target_close_rtp(struct target *t);
int target_cleanup_rtp(struct target *t);

#endif
