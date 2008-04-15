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


#ifndef __HELPER_RTP_H__
#define __HELPER_RTP_H__


#include "modules_common.h"
#include "helper.h"

#define HELPER_RTP_SEQ_KNOWN 1

struct helper_priv_rtp_packet {

	struct frame *f;
	uint16_t seq; ///< RTP sequence of this packet
	unsigned int data_len; ///< payload lenght of this packet
	struct helper_priv_rtp_packet *next;
	struct helper_priv_rtp_packet *prev;
};

struct helper_priv_rtp {

	uint16_t seq_expected[2];
	int flags[2];

	struct helper_priv_rtp_packet *pkts[2];
	struct helper_priv_rtp_packet *pkts_tail[2];
	unsigned int buff_len[2]; ///< Used to keep track of the total buffer length we have in memory for this connection

	struct timer *t[2];

	struct conntrack_entry *ce;

	struct helper_priv_rtp *prev;
	struct helper_priv_rtp *next;

};

struct helper_timer_priv_rtp {
	struct helper_priv_rtp *priv;
	int dir;
};

int helper_register_rtp(struct helper_reg *r);
int helper_need_help_rtp(struct frame *f, unsigned int start, unsigned int len, struct layer *l);
int helper_process_next_rtp(struct helper_priv_rtp *p, int dir);
int helper_process_timer_rtp(void *priv);
int helper_flush_buffer_rtp(struct conntrack_entry *ce, void *conntrack_priv);
int helper_unregister(int helper_type);
int helper_cleanup_connection_rtp(struct conntrack_entry *ce, void *conntrack_priv);
int helper_cleanup_rtp();

#endif

