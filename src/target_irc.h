/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2010 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  target_irc : Dump IRC communication
 *  Copyright (C) 2007 Gouverneur Thomas <wildcat@espix.org>
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

#ifndef __TARGET_IRC_H__
#define __TARGET_IRC_H__

#include "modules_common.h"
#include "rules.h"


#define TARGET_IRC_STATUS_CONV		"status"
#define TARGET_CMD_TIMEOUT_IRC		60
#define TARGET_MAX_LINE_IRC		512
#define TARGET_MAX_FROM_IRC		256

#define TARGET_QUERY_TIMEOUT_IRC	3600

#define is_chan(x) (*x == '#' || *x == '&' || *x == '+' || *x == '!')

#define TARGET_NICK_MODE_VOICED_IRC	0x1
#define TARGET_NICK_MODE_HALFOP_IRC	0x2
#define TARGET_NICK_MODE_OP_IRC		0x3

struct target_conv_list_irc {

	struct target_conversation_irc *conv;
	struct target_conv_list_irc *next;
	struct target_conv_list_irc *prev;

};

struct target_nick_list_irc {
	struct target_nick_irc *nick;
	unsigned int mode;

	struct target_nick_list_irc *next;
	struct target_nick_list_irc *prev;
};

struct target_nick_irc {

	char *nick;
	char *host;
	
	struct target_conv_list_irc *convs;

	struct target_nick_irc *next;
	struct target_nick_irc *prev;
};

enum irc_command_type {

	irc_cmd_privmsg,
	irc_cmd_nick,
	irc_cmd_join,
	irc_cmd_part,
	irc_cmd_mode,
	irc_cmd_oper,
	irc_cmd_kick,
	irc_cmd_topic,
	irc_cmd_quit,

// Todo
	irc_cmd_invite,
	irc_cmd_whois,
	irc_cmd_kill,

};

union irc_cmd_args {


	char *msg; // For PRIVMSG and others
	char *nick; // For NICK
	char *topic; // For TOPIC
	char *key; // For JOIN

	struct {
		char *what;
		char *modes;
	} mode;
	
	struct {
		char *who;
		char *reason;
	} kick;
	
	struct {
		char *user;
		char *pass;
	} oper;


};

struct target_command_irc {

	unsigned int type;

	union irc_cmd_args *args;

	struct timer *timeout;
	struct target_conversation_irc *conv;

	struct timeval ts;

	struct target_command_irc *next;
	struct target_command_irc *prev;

};

struct target_log_buffer_irc {
	char *buff;
	struct timeval ts;
	struct target_conversation_irc *conv;
	struct target_log_buffer_irc *next, *prev;
};

struct target_conversation_irc {

	char *who;
	int fd;
	char *filename;

	struct timer *expiry; // Timeout queries after a while

	struct target_command_irc *cmd_buff_head, *cmd_buff_tail;

	struct target_log_buffer_irc *log_buff_head, *log_buff_tail;

	struct target_conntrack_priv_irc *cp;

	struct target_nick_list_irc *nicks;

	struct target_conversation_irc *prev;
	struct target_conversation_irc *next;
};

struct target_conntrack_priv_irc {

	unsigned int is_invalid;

	struct conntrack_entry *ce;
	struct target_priv_irc *tp;

	// Nickname associated with the connection if found
	char nick[TARGET_MAX_FROM_IRC + 1];

	// Buffer
	char *buff[2];
	size_t buffpos[2], bufflen[2];

	struct target_conversation_irc *conv;
	struct target_nick_irc *nicks;

	struct target_log_buffer_irc *logs;

	struct target *t;

	struct target_conntrack_priv_irc *next;
	struct target_conntrack_priv_irc *prev;
};


struct target_priv_irc {

	struct ptype *path;

	struct target_conntrack_priv_irc *ct_privs;

};


int target_register_irc(struct target_reg *r);
static int target_init_irc(struct target *t);
static int target_process_irc(struct target *t, struct frame *f);
static int target_close_connection_irc(struct target *t, struct conntrack_entry *ce, void *conntrack_priv);
static int target_close_irc(struct target *t);
static int target_cleanup_irc(struct target *t);

/*
 * Contain the token of IRC message along with
 * the function to execute when parsed.
 */
struct irc_cmd_handler {
	char *cmd;
	int (*handler) (struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
};

// Command handlers

static int target_irc_handler_privmsg(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_notice(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_join(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_part(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_pass(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_user(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_nick(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_mode(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_topic(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_oper(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_kick(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_ping(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_pong(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_quit(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);

// Reply and error handlers
static int target_irc_handler_numeric_msg(struct target_conntrack_priv_irc *cp, struct frame *f, unsigned int code, struct target_nick_irc *from, char *args);


static struct target_nick_irc *target_add_nick_irc(struct target_conntrack_priv_irc *cp, char *nick, char *host);
static int target_parse_msg_irc(struct target_conntrack_priv_irc *cp, struct frame *f, char *line, size_t len);
static int target_queue_command_irc(struct target_conntrack_priv_irc *cp, struct frame *f, char *conv, unsigned int type, union irc_cmd_args *args);
static struct target_conversation_irc* target_get_conv_irc(struct target_conntrack_priv_irc *cp, char *conv, struct target_nick_irc *from, struct frame *f);
static int target_write_log_irc(int fd, char *buff, size_t count);
static int target_process_expired_commands_irc(void *priv);
static int target_log_irc(struct target_conversation_irc *c, struct timeval *when, const char *format, ...);
static int target_open_log_irc(struct target_conversation_irc *c);
static int target_add_conv_to_nick_irc(struct target_nick_irc *n, struct target_conversation_irc *conv);
static int target_remove_conv_from_nick_irc(struct target_nick_irc *n, struct target_conversation_irc *conv);
static int target_close_conv_irc(struct target_conversation_irc *c);
static struct target_command_irc* target_pop_buffered_command(struct target_conversation_irc *c, enum irc_command_type type, union irc_cmd_args *arg);


static int target_irc_handler_rpl_away(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_rpl_whoisuser(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_rpl_whoisserver(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_rpl_whoisidle(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_rpl_endofwhois(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_rpl_whoisaccount(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_rpl_whoischannels(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_rpl_namreply(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_rpl_endofnames(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_rpl_whoissecure(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);

static int target_irc_handler_err_nosuchnick(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_err_cannotsendtochan(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_join_err(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);
static int target_irc_handler_mode_user_err(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args);

static struct irc_cmd_handler irc_cmds[] = {
	{ "PRIVMSG", target_irc_handler_privmsg }, 
	{ "NOTICE", target_irc_handler_notice },
	{ "PART", target_irc_handler_part },
	{ "JOIN", target_irc_handler_join },
	{ "PASS", target_irc_handler_pass },
	{ "USER", target_irc_handler_user },
	{ "NICK", target_irc_handler_nick },
	{ "MODE", target_irc_handler_mode },
	{ "TOPIC", target_irc_handler_topic },
	{ "OPER", target_irc_handler_oper },
	{ "KICK", target_irc_handler_kick },
	{ "PING", target_irc_handler_ping },
	{ "PONG", target_irc_handler_pong },
	{ "QUIT", target_irc_handler_quit },


	{ NULL, NULL } // terminating entry
};

#endif
