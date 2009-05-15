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

enum msn_payload_type {
	
	msn_payload_type_unk = 0, ///< Unknown
	msn_payload_type_msg, ///< processing a message
	msn_payload_type_mail_invite, ///< user sent a mail invite
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
};

struct target_buddy_group_msn {

	char *name; // Name of the group
	char *id; // Could be just an int or a full winwin GUID

	struct target_buddy_group_msn *next;
};

struct target_buddy_msn {
	char *account;
	char *nick;
	char *group_list;

	struct target_buddy_msn *next;
};

struct target_session_priv_msn {

	int refcount; // Reference count for this MSN session

	struct target_buddy_msn *buddies; // Known buddies
	struct target_buddy_group_msn *groups; // Known group of buddies

	unsigned int version; // Protocol version for this connection
	char *account; // Account name of the user
	char *friendly_name; // Friendly name
	enum msn_status_type status; // Status (online, busy etc)

	int fd; // Session log file

	struct target_session_priv_msn *next;
	struct target_session_priv_msn *prev;

};

struct target_connection_party_msn {

	char *account;
	char *nick;
	int joined; // true if user has joined and is still connected
	struct target_connection_party_msn *next;
};

enum msn_file_type {
	msn_file_type_unknown = 0,
	msn_file_type_unsupported,
	msn_file_type_display_image,

};

struct target_file_transfer_msn {

	size_t len;
	size_t pos;
	enum msn_file_type type;
	uint32_t session_id;
	int fd;

	struct target_file_transfer_msn *next;
};

struct target_msg_msn {

	int payload_type, mime_type;
	int subtype;// used by each mime-type
	unsigned int cur_len, cur_pos, tot_len;

	char *from;
	char *to;
};

enum msn_evt_type {
	msn_evt_user_join = 0x0000,
	msn_evt_message,
	msn_evt_user_leave,
	msn_evt_friendly_name_change = 0x0100,
	msn_evt_status_change,
	msn_evt_user_disconnect,
	msn_evt_mail_invite,
};

struct target_event_msn {
	enum msn_evt_type type;
	struct timeval tv;
	char *from;
	char *to;
	char *buff;
	struct target_event_msn *next;
};

struct target_conntrack_priv_msn {

	int is_invalid; // Set to 1 when invalid payload was detected

	struct target_session_priv_msn *session; // Datas of the session
	struct target_connection_party_msn *parts; // Parties in the conversation

	unsigned int server_dir; // Direction of the messages sent by the server
	int curdir; // Id of current direction being processed
	
	char *buffer[2];
	unsigned int buffer_len[2];

	// Use when a file transfer occurs
	struct target_file_transfer_msn *file;

	// The following is only used when processing messages
	struct target_msg_msn *msg[2]; // Info about the message being processed

	// Buffer of conversation events while we still don't know the account
	struct target_event_msn *conv_buff;

	struct target_conntrack_priv_msn *next;
	struct target_conntrack_priv_msn *prev;

	struct conntrack_entry *ce; // Associated conntrack entry

	char *parsed_path; // Path were the files will be saved
	int fd; // File of the conversation if opened

};

struct target_priv_msn {

	struct ptype *path;
	struct target_conntrack_priv_msn *ct_privs;

	struct target_session_priv_msn *sessions; // Sessions for each users

};


struct msn_cmd_handler {
	char *cmd;
	int (*handler) (struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);

};


int target_register_msn(struct target_reg *r);

int target_init_msn(struct target *t);
int target_process_msn(struct target *t, struct frame *f);
int target_process_line_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_process_payload_ignore_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_close_connection_msn(struct target *t, struct conntrack_entry* ce, void *conntrack_priv);
int target_close_msn(struct target *t);
int target_cleanup_msn(struct target *t);

int target_msn_chk_conn_dir(struct target_conntrack_priv_msn *cp, unsigned int pkt_dr, int msn_dir);
struct target_conntrack_priv_msn* target_msn_conntrack_priv_fork(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_add_expectation(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, char *address);
int target_free_msg_msn(struct target_conntrack_priv_msn *cp, int dir);



#endif
