/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2008-2009 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __TARGET_MSN_MSGS_H__
#define __TARGET_MSN_MSGS_H__

#include "target_msn.h"

#define PNG_SIGNATURE "\211PNG\r\n\032\n"

#define MSN_SESSION_TIMEOUT 3600 // 10 minutes

struct msn_header {

	char *name;
	char *value;

};

struct msn_mime_type {

	char *name;
	int (*handler) (struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs);
};

/// WLM 2009 stuff

struct msn_stun_frame_layer_hdr {

	uint32_t len;
	uint32_t frame_type; // not sure
};

struct msn_tcp_frame_layer_hdr {
	uint32_t len;
};

struct msn_udp_frame_layer_hdr {

	uint32_t local_id;
	uint32_t remote_id;
	uint32_t unknown1;
	uint32_t unknown2;
	uint32_t unknown3;

};

struct msn_transport_layer_hdr {

	uint8_t hdr_len;
	uint8_t opcode;
	uint16_t data_len;
	uint32_t seq;
};

struct msn_data_layer_hdr {

	uint8_t hdr_len;
	uint8_t opcode;
	uint16_t seq;
	uint32_t session;

};


struct msn_tlv_hdr {
	uint8_t type;
	uint8_t len;
};


struct msn_file_transfer_context {

	uint32_t len;
	uint32_t unk;
	uint64_t file_size;
	uint32_t flags;
};

char* line_split(struct target_conntrack_priv_msn *cp);
struct msn_header *header_split(struct target_conntrack_priv_msn *cp);


int target_process_mime_msmsgscontrol_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs);
int target_process_mime_text_plain_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs);
int target_process_mime_msnmsgrp2p_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs);
int target_process_bin_p2p_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct target_buddy_msn *buddy_dest, char *buddy_guid);
int target_process_mail_notification_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs);
int target_process_msg_profile_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs);

int target_process_msg_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame*);
int target_process_mail_invite_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_process_status_msg_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);


int target_process_sip_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct target_buddy_msn *buddy_dest, char *buddy_guid);

int target_mirror_string_msn(char *value);
int target_session_timeout_msn(void *priv);
int target_session_close_file_msn(struct target_file_transfer_msn *file);

#endif
