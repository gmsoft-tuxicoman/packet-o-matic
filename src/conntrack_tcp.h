/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __CONNTRACK_TCP_H__
#define __CONNTRACK_TCP_H__


#include "modules_common.h"
#include "conntrack.h"

#define __FAVOR_BSD // We use BSD favor of the tcp header
#include <netinet/tcp.h>

#undef __FAVOR_BSD

enum
{
  STATE_TCP_ESTABLISHED = 1,
  STATE_TCP_SYN_SENT,
  STATE_TCP_SYN_RECV,  
  STATE_TCP_CLOSE,
  STATE_TCP_LAST_ACK,
  STATE_TCP_TIME_WAIT,
};


struct conntrack_priv_tcp {

	uint16_t sport;
	uint16_t dport;
	struct timer *timer;
	int state;

};

int conntrack_register_tcp(struct conntrack_reg *r);
static uint32_t conntrack_get_hash_tcp(struct frame *f, unsigned int start, unsigned int flags);
static int conntrack_doublecheck_tcp(struct frame *f, unsigned int start, void *priv, unsigned int flags);
static void *conntrack_alloc_match_priv_tcp(struct frame *f, unsigned int start, struct conntrack_entry *ce);
static int conntrack_cleanup_match_priv_tcp(void *priv);
static int conntrack_unregister_tcp(struct conntrack_reg *r);


static int conntrack_tcp_update_timer(struct conntrack_priv_tcp *priv, struct tcphdr *hdr);

#endif

