/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __HELPER_TCP_H__
#define __HELPER_TCP_H__


#include "modules_common.h"
#include "helper.h"

#define HELPER_TCP_SEQ_KNOWN 1

struct helper_priv_tcp_packet {

	struct frame *f;
	uint32_t seq; ///< TCP sequence of this packet
	uint32_t ack; ///< ACK contained is this packet
	unsigned int data_len; ///< payload lenght of this packet
	struct helper_priv_tcp_packet *next;
	struct helper_priv_tcp_packet *prev;
};

struct helper_priv_tcp {

	uint32_t last_seq[2];
	uint32_t seq_expected[2];
	int flags[2];

	struct helper_priv_tcp_packet *pkts[2];
	struct helper_priv_tcp_packet *pkts_tail[2];
	unsigned int buff_len[2]; ///< Used to keep track of the total buffer length we have in memory for this connection

	struct timer *t[2];

	struct conntrack_entry *ce;

	struct helper_priv_tcp *prev;
	struct helper_priv_tcp *next;

};

struct helper_timer_priv_tcp {
	struct helper_priv_tcp *priv;
	int dir;
};

int helper_register_tcp(struct helper_reg *r);
static int helper_need_help_tcp(struct frame *f, unsigned int start, unsigned int len, struct layer *l);
static int helper_process_next_tcp(struct helper_priv_tcp *p, int dir);
static int helper_process_timer_tcp(void *priv);
static int helper_flush_buffer_tcp(struct conntrack_entry *ce, void *conntrack_priv);
static int helper_cleanup_connection_tcp(struct conntrack_entry *ce, void *conntrack_priv);
static int helper_cleanup_tcp();

#endif

