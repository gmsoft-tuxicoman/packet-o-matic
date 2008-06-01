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


#ifndef __TARGET_RTP_H__
#define __TARGET_RTP_H__


#include "modules_common.h"
#include "rules.h"



#define RTP_CODEC_G711U	0
#define RTP_CODEC_G721	2
#define RTP_CODEC_G711A	8
#define RTP_CODEC_G722	9


#define AU_CODEC_MULAW		1
#define AU_CODEC_ADPCM_G721	23
#define AU_CODEC_ADPCM_G722	24
#define AU_CODEC_ALAW		27

#define AU_MAGIC ".snd"

#define AU_UNKNOWN_SIZE (~0) // -1

struct au_hdr {

	char magic[4];
	uint32_t hdr_size;
	uint32_t data_size;
	uint32_t encoding;
	uint32_t sample_rate;
	uint32_t channels;


};

struct rtp_buffer {

	char *buff;
	unsigned int buff_size;
	unsigned int buff_pos;
	int direction;

};


struct target_conntrack_priv_rtp {

	char filename[NAME_MAX + 1];
	int fd;
	uint16_t last_seq[2];
	uint32_t total_size;
	uint32_t payload_type;

	struct conntrack_entry *ce;

	struct rtp_buffer buffer[2];
	int channels;

	struct target_conntrack_priv_rtp *next;
	struct target_conntrack_priv_rtp *prev;

};

struct target_priv_rtp {

	struct ptype *prefix;
	struct ptype *jitter_buffer;

	struct target_conntrack_priv_rtp *ct_privs;

};

int target_register_rtp(struct target_reg *r);

static int target_init_rtp(struct target *t);
static int target_process_rtp(struct target *t, struct frame *f);
static int target_close_connection_rtp(struct target *t, struct conntrack_entry *ce, void *conntrack_priv);
static int target_close_rtp(struct target *t);
static int target_cleanup_rtp(struct target *t);

static int write_packet(struct target_conntrack_priv_rtp *cp, struct target_priv_rtp *priv, int dir, void *data, int len);
static int open_file(struct target_priv_rtp *priv, struct target_conntrack_priv_rtp *cp);
static int flush_buffers(struct target_conntrack_priv_rtp *cp, int dir);

#endif
