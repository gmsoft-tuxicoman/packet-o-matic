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


#ifndef __CONNTRACK_RTP_H__
#define __CONNTRACK_RTP_H__


#include "modules_common.h"
#include "conntrack.h"

struct conntrack_priv_rtp {

	__u32 ssrc;
	__u8 payload_type;
	struct conntrack_timer *timer;

};

int conntrack_register_rtp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs);
__u32 conntrack_get_hash_rtp(void *frame, unsigned int start);
int conntrack_doublecheck_rtp(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce);
void *conntrack_alloc_match_priv_rtp(void *frame, unsigned int start, struct conntrack_entry *ce);
int conntrack_cleanup_match_priv_rtp(void *priv);
int conntrack_do_timeouts_rtp( int (*conntrack_close_connection) (struct conntrack_entry *ce));

#endif

