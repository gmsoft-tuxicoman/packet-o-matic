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


#ifndef __TARGET_MSN_H__
#define __TARGET_MSN_H__


#include "modules_common.h"
#include "rules.h"

#define MSN_EXPECTATION_TIMER 180

#define MSN_DIR_UNK		0
#define MSN_DIR_FROM_CLIENT	1
#define MSN_DIR_FROM_SERVER	2

// check if and event needs the session or the connection file
#define MSN_EVT_SESSION_MASK	0xff00

#define TARGET_MSN_BUDDY_TABLE_SIZE 8192

enum msn_payload_type {
	
	msn_payload_type_unk = 0, ///< Unknown
	msn_payload_type_msg, ///< processing a message
	msn_payload_type_mail_invite, ///< user sent a mail invite
	msn_payload_type_status_msg, ///< status message and other info
	msn_payload_type_adl, ///< Payload from the ADL command, contains the contact list
	msn_payload_type_sip_msg, ///< Raw SIP message
	msn_payload_type_uun_ubn, ///< Message from a UUN or UBN command
	msn_payload_type_p2p, ///< Message is from a P2P connection
	msn_payload_type_ignore, ///< Ignore/unhandled payload
};

enum msn_status_type {
	msn_status_unknown = 0,
	msn_status_available,
	msn_status_busy,
	msn_status_idle,
	msn_status_brb,
	msn_status_away,
	msn_status_phone,
	msn_status_lunch,
	msn_status_hidden,
	msn_status_offline,
};

struct target_buddy_list_msn {

	struct target_buddy_msn *bud;
	struct target_buddy_list_msn *next;

};

struct target_buddy_list_session_msn {

	struct target_buddy_msn *bud;
	int blocked; // True if user is blocked
	struct target_buddy_list_session_msn *next;

};

struct target_session_list_msn {

	struct target_session_priv_msn *sess;
	struct target_session_list_msn *next;
};

struct target_buddy_msn {
	char *account; // Account for this user
	char *nick; // Friendly name of the user
	enum msn_status_type status; // Status of this user
	char *psm; // Personal message of the user
	struct target_session_list_msn *sess_lst; // Sessions to which this buddy is in
};

struct target_session_priv_msn {

	int refcount; // Reference count for this MSN session

	struct target_buddy_list_session_msn *buddies; // Known buddies

	unsigned int version; // Protocol version for this connection

	struct target_buddy_msn *user; // User who logged in

	// Buffer of conversation events while we still don't know the account
	struct target_event_msn *evt_buff;

	struct target_conversation_msn *conv; // All the conversations from this session

	int fd; // Session log file

	// Use when a file transfer occurs
	struct target_file_transfer_msn *file;

	char *parsed_path; // Path were the files will be saved
	struct target_priv_msn *target_priv;

	struct target_session_priv_msn *next;
	struct target_session_priv_msn *prev;

};

struct target_connection_party_msn {

	struct target_buddy_msn *buddy; // point to the corresponding buddy
	int joined; // true if user has joined
	struct target_connection_party_msn *next;
};

enum msn_file_type {
	msn_file_type_unknown = 0,
	msn_file_type_unsupported,
	msn_file_type_display_image,
	msn_file_type_transfer,
};

struct target_bin_msg_buff_msn {

	char *buffer;
	unsigned int total_size, cur_pos;
};

struct target_file_transfer_msn {

	size_t len; // Total file length
	size_t pos; // Current writing position (can go backward when chunks are received out of order)
	size_t written_len; // Number of bytes written to the file
	enum msn_file_type type;
	uint32_t session_id;
	int fd;
	struct target_buddy_msn *buddy; // User who we are exchanging the file with
	char *buddy_guid;
	char *filename;
	struct timer* timer;

	struct target_conversation_msn *conv; // Conversation to which this file belongs
	struct target_file_transfer_msn *next;
	struct target_file_transfer_msn *prev;
};

enum msn_sip_cmd_type {
	msn_msnmsgrp2p_sip_type_unknown = 0,
	msn_msnmsgrp2p_sip_type_invite,
	msn_msnmsgrp2p_sip_type_200_ok,
	msn_msnmsgrp2p_sip_type_ack,
	msn_msnmsgrp2p_sip_type_bye,
	msn_msnmsgrp2p_sip_type_error,
	msn_msnmsgrp2p_sip_type_payload,
};

struct target_msg_msn {

	int payload_type, mime_type;
	enum msn_sip_cmd_type sip_cmd;
	unsigned int cur_len, tot_len; // Current write position and total length
	unsigned int cur_pos; // Current read position

	struct target_buddy_msn *from;
	struct target_buddy_msn *to;
};

enum msn_evt_type {
	msn_evt_buddy_join = 0x0000,
	msn_evt_message,
	msn_evt_buddy_leave,
	msn_evt_nudge,
	msn_evt_wink,
	msn_evt_file_transfer_start,
	msn_evt_file_transfer_end,
	msn_evt_session_start = 0x0100,
	msn_evt_friendly_name_change,
	msn_evt_status_change,
	msn_evt_user_disconnect,
	msn_evt_mail_invite,
	msn_evt_personal_msg_change,
	msn_evt_user_added,
	msn_evt_user_blocked,
	msn_evt_user_unblocked,
};

struct target_event_msn {
	enum msn_evt_type type;
	struct target_session_priv_msn *sess;
	struct target_conversation_msn *conv;
	struct timeval tv;
	struct target_buddy_msn *from;
	struct target_buddy_msn *to;
	char *buff;
	struct target_event_msn *next;
};

#define MSN_CONN_FLAG_INVALID		0x01 // Set if the connection has been marked as invalid
#define MSN_CONN_FLAG_P2P		0x02 // Set if this is a direct P2P connection
#define MSN_CONN_FLAG_STUN		0x04 // Set if this is a STUN connection to a relay server
#define MSN_CONN_FLAG_WLM2009_BIN	0x08 // Set if the connection will use the WLM2009 binary header format
#define MSN_CONN_FLAG_UDP		0x10 // Set if the connection needs UDP expectations

struct target_conversation_msn {
	
	int fd; // File of the conversation if opened

	struct target_connection_party_msn *parts; // Parties in the conversation

	// Buffer of conversation events while we still don't know the account
	struct target_event_msn *evt_buff;

	unsigned int refcount;
	
	struct target_session_priv_msn *sess; // Session to which this conversation belongs

	struct target_conversation_msn *next;
	struct target_conversation_msn *prev;

};

struct target_conntrack_priv_msn {

	unsigned int flags;

	struct target_session_priv_msn *session; // Datas of the session

	unsigned int server_dir; // Direction of the messages sent by the server
	int curdir; // Id of current direction being processed
	
	char *buffer[2];
	unsigned int buffer_len[2];

	// The following is only used when processing messages
	struct target_msg_msn *msg[2]; // Info about the message being processed

	// Buffer for splitted SIP messages
	struct target_bin_msg_buff_msn *sip_msg_buff[2];

	// Conversation associated with this connection
	struct target_conversation_msn *conv;

	struct target_conntrack_priv_msn *next;
	struct target_conntrack_priv_msn *prev;

	struct conntrack_entry *ce; // Associated conntrack entry

	struct target_priv_msn *target_priv;

};

struct target_priv_msn {

	struct ptype *path;
	struct ptype *dump_session;
	struct ptype *dump_avatar;
	struct ptype *dump_file_transfer;

	struct target_conntrack_priv_msn *ct_privs;

	struct target_session_priv_msn *sessions; // Sessions for each users

	struct target_buddy_list_msn **buddy_table;

};


struct msn_cmd_handler {
	char *cmd;
	int (*handler) (struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);

};


int target_register_msn(struct target_reg *r);

int target_init_msn(struct target *t);
int target_open_msn(struct target *t);
int target_process_msn(struct target *t, struct frame *f);
int target_process_line_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_process_payload_ignore_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_close_connection_msn(struct target *t, struct conntrack_entry* ce, void *conntrack_priv);
int target_close_msn(struct target *t);
int target_cleanup_msn(struct target *t);

int target_msn_chk_conn_dir(struct target_conntrack_priv_msn *cp, unsigned int pkt_dr, int msn_dir);
struct target_conntrack_priv_msn* target_msn_conntrack_priv_fork(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_add_expectation_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, char *address, char *port, unsigned int flags);
int target_free_msg_msn(struct target_conntrack_priv_msn *cp, int dir);



#endif
