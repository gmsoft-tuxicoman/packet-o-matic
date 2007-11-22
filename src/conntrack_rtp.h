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


#ifndef __CONNTRACK_RTP_H__
#define __CONNTRACK_RTP_H__


#include "modules_common.h"
#include "conntrack.h"

struct conntrack_priv_rtp {

	uint32_t ssrc;
	uint8_t payload_type;
	struct timer *timer;

};

int conntrack_register_rtp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs);
uint32_t conntrack_get_hash_rtp(struct frame *f, unsigned int start, unsigned int flags);
int conntrack_doublecheck_rtp(struct frame *f, unsigned int start, void *priv, unsigned int flags);
void *conntrack_alloc_match_priv_rtp(struct frame *f, unsigned int start, struct conntrack_entry *ce);
int conntrack_cleanup_match_priv_rtp(void *priv);
int conntrack_do_timeouts_rtp( int (*conntrack_close_connection) (struct conntrack_entry *ce));
int conntrack_unregister_rtp(struct conntrack_reg *r);

#endif

