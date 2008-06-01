/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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

#define IRC_MATCH	0x01
#define IRC_NOMATCH	0x02
#define IRC_UNKNOWN	0x04

#include "modules_common.h"
#include "rules.h"

#define MAX_LINE	512
#define MAX_FROM	256
#define MAX_TOK		15
#define MAX_CHANNEL	32
#define MAX_NICK	32

/*
 * Openned files mgr
 */
struct open_file {

	int fd;
	char what[MAX_NICK + 1];

	struct open_file *n;
	struct open_file *p;
};

struct target_conntrack_priv_irc {

	int fd; // FD for status file.
	struct open_file *ofiles;

	struct frame *f;

	unsigned int state;
	unsigned int direction;
	unsigned int pos;

	struct conntrack_entry *ce;
	struct target_conntrack_priv_irc *next;
	struct target_conntrack_priv_irc *prev;

	/* 
	 * struct target * to avoid passing it by arg 
	 */
	struct target *t;
	struct target_priv_irc *tp;

	/*
	 * IRC Stuff:
	 */
	char	my_nick[MAX_NICK + 1];
};


struct target_priv_irc {

	int match_mask;

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
struct irc_tok {
	char * token;
	int (*cb)(struct target_conntrack_priv_irc *,	/* context of target_irc */
		  unsigned int is_srv,			/* comming from srv ? */
		  char *from,				/* origin of msg */
		  char *line
		  );
	unsigned int is_pass;
};

/* utility functions */
static int 	add_of(struct open_file*, struct open_file*);
static struct 	open_file* get_of(struct open_file*, const char* what);
static int 	open_of(struct open_file*, struct target_conntrack_priv_irc*);
static int 	remove_all_of(struct open_file*);
static char*	get_timestamp(void);
static char*	get_time(void);
static char*	getNick(char *);

/* irc processing functions */
#define TOKEN_FCT(x) 	static int x(	struct target_conntrack_priv_irc *, \
					unsigned int is_srv, \
					char *from, \
					char *line);

TOKEN_FCT(process_privmsg);
TOKEN_FCT(process_notice);
TOKEN_FCT(process_join);
TOKEN_FCT(process_part);
TOKEN_FCT(process_pass);
TOKEN_FCT(process_nick);
TOKEN_FCT(process_mode);
TOKEN_FCT(process_topic);
TOKEN_FCT(process_oper);
TOKEN_FCT(process_kick);

static int parse_msg(struct target_conntrack_priv_irc *,
		  char * line,
		  unsigned int len);

#define NB_TOKENS 10
static struct irc_tok Irc_MSG[] = {
	{ "PRIVMSG", process_privmsg, 0 }, 	/* no password in PRIVMSG */
	{ "NOTICE", process_notice, 0 }, 	/* no password in NOTICE */
	{ "PART", process_part, 0 },		/* no password in PART */
	{ "JOIN", process_join, 1 }, 		/* could have a password in JOIN */
	{ "PASS", process_pass, 1 }, 		/* password to log on server */
	{ "NICK", process_nick, 0 }, 		/* nickname change */
	{ "MODE", process_mode, 0 }, 		/* mode change */
	{ "TOPIC", process_topic, 0 }, 		/* topic check/change */
	{ "OPER", process_oper, 1 }, 		/* ircop login */
	{ "KICK", process_kick, 0 } 		/* kick */
};

#endif
