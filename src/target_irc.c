/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2010 Guy Martin <gmsoft@tuxicoman.be>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#include "target_irc.h"

#include "ptype_bool.h"
#include "ptype_string.h"


static unsigned int match_undefined_id;
static struct target_mode *mode_dump;


int target_register_irc(struct target_reg *r) {

	r->init = target_init_irc;
	r->process = target_process_irc;
	r->close = target_close_irc;
	r->cleanup = target_cleanup_irc;

	match_undefined_id = match_register("undefined");

	mode_dump = target_register_mode(r->type, "dump", "Dump IRC connection into separate files with irssi-like log format");

	if (!mode_dump)
		return POM_ERR;

	target_register_param(mode_dump, "path", "/tmp", "Path of dumped files");

	return POM_OK;

}


static int target_init_irc(struct target *t) {

	struct target_priv_irc *priv = malloc(sizeof(struct target_priv_irc));
	memset(priv, 0, sizeof(struct target_priv_irc));

	t->target_priv = priv;

	priv->path = ptype_alloc("string", NULL);

	if (!priv->path) {
		target_cleanup_irc(t);
		return POM_ERR;
	}
	
	target_register_param_value(t, mode_dump, "path", priv->path);

	return POM_OK;
}

static int target_close_irc(struct target *t) {

	struct target_priv_irc *priv = t->target_priv;

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_irc(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

static int target_cleanup_irc(struct target *t) {

	struct target_priv_irc *priv = t->target_priv;

	if (priv) {

		ptype_cleanup(priv->path);
		free(priv);
	}

	return POM_OK;
}

static int target_process_irc(struct target *t, struct frame *f) {

	struct target_priv_irc *priv = t->target_priv;
	struct layer *lastl = f->l;

	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	if (!f->ce)
		if (conntrack_create_entry(f) == POM_ERR)
			return POM_OK;

	int dir = 0;
	if (f->ce->direction == CE_DIR_FWD) {
		dir = 0;
	} else {
		dir = 1;
	}

	struct target_conntrack_priv_irc *cp;

	cp = conntrack_get_target_priv(t, f->ce);

	if (!cp) { // We need to track all connections

		cp = malloc(sizeof(struct target_conntrack_priv_irc));
		memset(cp, 0, sizeof(struct target_conntrack_priv_irc));

		cp->t = t;

		conntrack_add_target_priv(cp, t, f->ce, target_close_connection_irc);

		strcpy(cp->nick, "unknown_nick");

		cp->ce = f->ce;
		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;

	}
	if (cp->is_invalid) {
		if (cp->buff[0]) {
			free(cp->buff[0]);
			cp->buff[0] = NULL;
		}
		if (cp->buff[1]) {
			free(cp->buff[1]);
			cp->buff[1] = NULL;
		}
		return POM_OK;
	}

	if (lastl->payload_size == 0)
		return POM_OK;

	unsigned int pstart, psize;
	pstart = lastl->payload_start;
	psize = lastl->payload_size;

        char *pload = f->buff + lastl->payload_start;

	int i;
	for (i = 0; i < psize; i++) {
	 
		if (pload[i] == '\n') {

			if (cp->buffpos[dir] + i > TARGET_MAX_LINE_IRC) {
				cp->is_invalid = 1;
				pom_log(POM_LOG_DEBUG "Line too long -> connection invalid");
				free(cp->buff[dir]);
				cp->buff[dir] = 0;
				cp->bufflen[dir] = 0;
				cp->buffpos[dir] = 0;
				return POM_OK;
			}
			
			size_t line_len = cp->buffpos[dir] + i;
			size_t tmp_len = i;
			if (i > 0 && pload[i - 1] == '\r') {
				line_len--;
				tmp_len--;
			}

			if (cp->bufflen[dir] <= line_len) {
				cp->buff[dir] = realloc(cp->buff[dir], line_len + 1);
				cp->bufflen[dir] = line_len + 1;
			}

			memcpy(cp->buff[dir] + cp->buffpos[dir], pload, tmp_len);
			cp->buffpos[dir] += tmp_len;
			cp->buff[dir][line_len] = 0;

			// parse line
			cp->tp = priv;
			target_parse_msg_irc(cp, f, cp->buff[dir], cp->buffpos[dir]);
			cp->buffpos[dir] = 0;

			// go to next item in payload
			psize -= i + 1;
			pload += i + 1;
			i = 0;
		}
	}

	if (psize) { // Stuff remaining in the payload
		
		size_t size = cp->buffpos[dir] + psize;
		if (cp->bufflen[dir] < size) {
			cp->buff[dir] = realloc(cp->buff[dir], size + 1);
			cp->bufflen[dir] = size + 1;
		}
		memcpy(cp->buff[dir] + cp->buffpos[dir], pload, psize);
		cp->buffpos[dir] = size;
	}


	return POM_OK;
}

static int target_close_connection_irc(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_irc *cp;
	cp = conntrack_priv;

	struct target_priv_irc *priv = t->target_priv;

	// Free conversations
	while (cp->conv)
		target_close_conv_irc(cp->conv);

	// Remove the connection from the list
	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;


	// Free nicks
	struct target_nick_irc *n = cp->nicks;
	while (n) {
		cp->nicks = n->next;
		// Free conversation of each nick
		struct target_conv_list_irc *cl = n->convs;
		while (cl) {
			n->convs = cl->next;
			free(cl);
			cl = n->convs;
		}
		free(n->nick);
		if (n->host)
			free(n->host);
		free(n);

		n = cp->nicks;
	}

	
	if (cp->buff[0])
		free(cp->buff[0]);
	if (cp->buff[1])
		free(cp->buff[1]);

	free(cp);

	return POM_OK;
}


static struct target_nick_irc *target_add_nick_irc(struct target_conntrack_priv_irc *cp, char *nick, char *host) {

	struct target_nick_irc *res = malloc(sizeof(struct target_nick_irc));
	memset(res, 0, sizeof(struct target_nick_irc));
	res->nick = strdup(nick);

	if (host)
		res->host = strdup(host);

	if (cp->nicks) {
		res->next = cp->nicks;
		cp->nicks->prev = res;
	}

	cp->nicks = res;

	return res;
}


static int target_parse_msg_irc(struct target_conntrack_priv_irc *cp, struct frame *f, char *line, size_t len) {

	int i;

	if (!len)
		return POM_OK;

	struct target_nick_irc *from = NULL;
	
	while (*line && *line == ' ')
		line++;

	if (*line == ':') {
		line++;
		char *end = strchr(line, ' ');
		if (!end) {
			pom_log(POM_LOG_DEBUG "Line with only from field");
			cp->is_invalid = 1;
			return POM_OK;
		}
		*end = 0;
		char *nick = line;
		// Strip host part from 'from'
		char *host = strchr(nick, '!');
		if (host) {
			*host = 0;
			host++;
		}

		// Find the right nick
		from = cp->nicks;
		while (from) {
			if (!strcmp(from->nick, nick))
				break;
			from = from->next;
		}
		if (!from) { // Nick not found
			from = target_add_nick_irc(cp, nick, host);
		}

		if (host && (!from->host || strcmp(from->host, host))) {
			if (from->host)
				free(from->host);
			from->host = strdup(host);
		}

		line = end + 1;
		while (*line && *line == ' ')
			line++;

		//pom_log(POM_LOG_TSHOOT "Server command from %s", from->nick);

	}

	char *cmd = line;

	char *args = strchr(cmd, ' ');
	if (args) { // this command has some arguments
		*args = 0;
		do {
			args++;
		} while (*args == ' ');
		pom_log(POM_LOG_TSHOOT "Command : %s %s", cmd, args);
	} else {
		pom_log(POM_LOG_DEBUG "Command without argument : %s", cmd);
		return POM_OK;
	}

	for (i = 0; irc_cmds[i].cmd; i++) {
		
		if (!strcasecmp(cmd, irc_cmds[i].cmd)) {
			return irc_cmds[i].handler(cp, f, from, args);
		}
	}

	// Let's see if we have a numeric command
	if (strlen(cmd) == 3 && cmd[0] >= '0' && cmd[0] <= '9' && cmd[1] >= '0' && cmd[1] <= '9' && cmd[2] >= '0' && cmd[2] <= '9') {
		unsigned int code = 0;
		sscanf(cmd, "%u", &code);
		return target_irc_handler_numeric_msg(cp, f, code, from, args);
	}
		

	pom_log(POM_LOG_DEBUG "Unhandled IRC command : %s", cmd);

	return POM_OK;
}


static int target_irc_handler_privmsg(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {
	
	// Find destination(s)
	char *sep = strchr(args, ' ');
	if (!sep) {
		pom_log(POM_LOG_DEBUG "PRIVMSG without actual message : %s", args);
		return POM_OK;
	}

	*sep = 0;
	do {
		sep++;
	} while (*sep == ' ' || *sep == ':');

	char *conv = args;
	if (from && !is_chan(args)) // If message is not to a chan and not from the client, it's a query with the client
		conv = from->nick;

	if (!from) {
		union irc_cmd_args *cmd_args = malloc(sizeof(union irc_cmd_args));
		memset(cmd_args, 0, sizeof(union irc_cmd_args));
		cmd_args->msg = strdup(sep);
		return target_queue_command_irc(cp, f, conv, irc_cmd_privmsg, cmd_args);
	}


	struct target_conversation_irc *c = target_get_conv_irc(cp, conv, from, f);
	return target_log_irc(c, &f->tv, "<%s> %s", from->nick, sep);

}


static int target_irc_handler_mode(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *sep = strchr(args, ' ');
	if (!sep) {
		pom_log(POM_LOG_DEBUG "MODE message without destination : %s", args);
		return POM_OK;
	}

	*sep = 0;
	
	// sep is the mode arguments
	do {
		sep++;
	} while (*sep == ' ' || *sep == ':');


	if (!strlen(sep) || (*sep != '+' || *sep != '-')) // Mode request only
		return POM_OK;

	struct target_conversation_irc *c = NULL;

	if (!from) { // Message from the client
		union irc_cmd_args *cmd_args = malloc(sizeof(union irc_cmd_args));
		memset(cmd_args, 0, sizeof(union irc_cmd_args));
		cmd_args->mode.what = strdup(args);
		cmd_args->mode.modes = strdup(sep);
		char *conv = args;
		if (!is_chan(conv))
			return target_queue_command_irc(cp, f, TARGET_IRC_STATUS_CONV, irc_cmd_mode, cmd_args);
		return target_queue_command_irc(cp, f, conv, irc_cmd_mode, cmd_args);
	}


	if (!is_chan(args)) { // User set mode for himself
		c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);
		strncpy(cp->nick, from->nick, TARGET_MAX_FROM_IRC);
		return target_log_irc(c, &f->tv, "-!- Mode change [%s] for user %s", sep, from->nick);
	}
	c = target_get_conv_irc(cp, args, from, f);
	return target_log_irc(c, &f->tv, "-!- mode/%s [%s] by %s", args, sep, from->nick);

}


static int target_irc_handler_oper(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *conv = TARGET_IRC_STATUS_CONV;

	char *sep = strchr(args, ' ' );
	if (!sep) {
		pom_log(POM_LOG_DEBUG "OPER command without password : %s", args);
		return POM_OK;
	}

	*sep = 0;
	do {
		sep++;
	} while (*sep == ' ');

	union irc_cmd_args *cmd_args = malloc(sizeof(union irc_cmd_args));
	memset(cmd_args, 0, sizeof(union irc_cmd_args));
	cmd_args->oper.user = strdup(args);
	cmd_args->oper.pass = strdup(sep);

	return target_queue_command_irc(cp, f, conv, irc_cmd_oper, cmd_args);

}


static int target_irc_handler_kick(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *sep = strchr(args, ' ');
	if (!sep) {
		pom_log(POM_LOG_DEBUG "KICK command without channel : %s", args);
		return POM_OK;
	}

	*sep = 0;
	do {
		sep++;
	} while (*sep == ' ');

	char *who = sep;
	sep = strchr(sep, ' ');
	if (!sep) {
		pom_log(POM_LOG_DEBUG "KICK command without nick : %s", sep);
		return POM_OK;
	}

	*sep = 0;
	do {
		sep++;
	} while (*sep == ' ' || *sep == ':');

	// sep is the kick reason
	

	if (!from) { // Message from the client
		union irc_cmd_args *cmd_args = malloc(sizeof(union irc_cmd_args));
		memset(cmd_args, 0, sizeof(union irc_cmd_args));
		cmd_args->kick.who = strdup(who);
		if (strlen(sep))
			cmd_args->kick.reason = strdup(sep);
		// Queue the kick command
		return target_queue_command_irc(cp, f, args, irc_cmd_kick, cmd_args);
	}
	
	struct target_conversation_irc *c = target_get_conv_irc(cp, args, from, f);

	int res = POM_ERR;
	if (!strlen(sep)) 
		res = target_log_irc(c, &f->tv, "-!- %s was kicked from %s by %s without reason", who, args, from->nick);
	else
		res = target_log_irc(c, &f->tv, "-!- %s was kicked from %s by %s [%s]", who, args, from->nick, sep);

	struct target_nick_irc *n;
	for (n = cp->nicks; n; n = n->next) {
		if (!strcasecmp(n->nick, who)) {
			target_remove_conv_from_nick_irc(n, c);
			break;
		}
	}

	return res;
}

static int target_irc_handler_topic(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *sep = strchr(args, ' ');
	if (!sep) // topic
		return POM_OK;

	*sep = 0;
	
	sep = strchr(sep, ':');
	if (!sep) // topic
		return POM_OK;
	sep++;

	if (!from) { // Message from the client
		union irc_cmd_args *cmd_args = malloc(sizeof(union irc_cmd_args));
		memset(cmd_args, 0, sizeof(union irc_cmd_args));
		if (strlen(sep))
			cmd_args->topic = strdup(sep);
		// Queue the topic command
		return target_queue_command_irc(cp, f, args, irc_cmd_topic, cmd_args);
	}

	struct target_conversation_irc *c = target_get_conv_irc(cp, args, from, f);
	if (strlen(sep))
		return target_log_irc(c, &f->tv, "-!- %s changed the topic of %s to: %s", from->nick, args, sep);
	return target_log_irc(c, &f->tv, "-!- Topic unset by %s on %s", from->nick, args);

}

static int target_irc_handler_user(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	if (from) {
		pom_log(POM_LOG_DEBUG "USER command received from the server side. Ignoring");
		return POM_OK;
	}

	char *hostname = strchr(args, ' ');
	if (!hostname) {
		pom_log(POM_LOG_DEBUG "USER command without hostname");
		return POM_OK;
	}

	*hostname = 0;
	do {
		hostname++;
	} while (*hostname == ' ');

	char *servername = strchr(hostname, ' ');
	if (!servername) {
		pom_log(POM_LOG_DEBUG "USER command without servername");
		return POM_OK;
	}
	*servername = 0;
	do {
		servername++;
	} while (*servername == ' ');

	char *realname = strchr(servername, ' ');
	if (!realname) {
		pom_log(POM_LOG_DEBUG "USER command without realname");
		return POM_OK;
	}
	*realname = 0;
	do {
		realname++;
	} while (*realname == ' ' || *realname == ':');

	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, NULL, f);
	return target_log_irc(c, &f->tv, "-!- Connecting with username \"%s\", hostname \"%s\", realname \"%s\" to server %s", args, hostname, realname, servername);
}

static int target_irc_handler_nick(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	while (*args == ' ' || *args == ':')
		args++;

	if (!from) { // Message from the client

		union irc_cmd_args *cmd_args = malloc(sizeof(union irc_cmd_args));
		memset(cmd_args, 0, sizeof(union irc_cmd_args));
		cmd_args->nick = strdup(args);
		// Queue the nick command
		return target_queue_command_irc(cp, f, TARGET_IRC_STATUS_CONV, irc_cmd_nick, cmd_args);
		
	}

	union irc_cmd_args cmd_args;
	cmd_args.nick = args;
	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, NULL, f);
	struct target_command_irc *cmd = target_pop_buffered_command(c, irc_cmd_nick, &cmd_args);

	if (cmd) {
		// Command was found, user changed his nick
		free(cmd->args->nick);
		free(cmd->args);
		free(cmd);
		int res = POM_OK;
		for (c = cp->conv; c; c = c->next) {
			res += target_log_irc(c, &f->tv, "-!- Client is now known as %s (was %s)", args, cp->nick);

		}
		strncpy(cp->nick, args, TARGET_MAX_FROM_IRC);

		return res;
	}

	// Update the nick
	char *old_nick = from->nick;
	from->nick = strdup(args);
	
	
	// Send this in the right conversation
	struct target_conv_list_irc *l = from->convs;
	int found = 0, res = POM_OK; // 0
	while (l) {
		res += target_log_irc(l->conv, &f->tv, "-!- %s is now known as %s", old_nick, args);
		found = 1;
		l = l->next;
	}

	if (found) {
		free(old_nick);
		return res;
	}

	c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);
	res = target_log_irc(c, &f->tv, "-!- %s is now known as %s", old_nick, args);
	free(old_nick);
	return res;

}

static int target_irc_handler_pass(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	while (*args == ' ')
		args++;
	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);	
	return target_log_irc(c, &f->tv, "-!- User connected with password \"%s\"", args);
}

static int target_irc_handler_join(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	while (*args == ' ' || *args == ':')
		args++;

	if (from) { // Someone (or ourself) joined a chan we already joined
		struct target_conversation_irc *c = target_get_conv_irc(cp, args, from, f);

		// Remove join command if it's from us
		struct target_command_irc *cmd = target_pop_buffered_command(c, irc_cmd_join, NULL);

		if (cmd) {
			int res = POM_OK;
			if (cmd->args->key) {
				res = target_log_irc(c, &f->tv, "-!- %s [%s] has joined %s using key %s", from->nick, from->host, args, cmd->args->key);
				free(cmd->args->key);
			} else {
				res = target_log_irc(c, &f->tv, "-!- %s [%s] has joined %s", from->nick, from->host, args);
				// First join is from ourself, update our nick
				strncpy(cp->nick, from->nick, TARGET_MAX_FROM_IRC);
			}
			free(cmd->args);
			free(cmd);

			return res;
		}

		return target_log_irc(c, &f->tv, "-!- %s [%s] has joined %s", from->nick, from->host, args);
	}

	char *keys_str = strchr(args, ' ');
	int keynum = 0;
	char **keys = NULL;
	if (keys_str) {
		*keys_str = 0;
		do {
			keys_str++;
		} while (*keys_str == ' ');
	
		char *sep = NULL;
		while (1) {
			sep = strchr(keys_str, ',');
			if (sep)
				*sep = 0;
			keynum++;
			keys = realloc(keys, sizeof(char*) * keynum);
			if (strlen(keys_str))
				keys[keynum - 1] = keys_str;
			else
				keys[keynum - 1] = NULL;

			if (!sep)
				break;

			keys_str = sep + 1;
		}

	}
	
	int channum = 0;
	char **chans = NULL;

	char *str, *token, *saveptr = NULL;
	for (str = args; ; str = NULL) {
		token = strtok_r(str, ",", &saveptr);
		if (!token)
			break;
		channum++;
		chans = realloc(chans, sizeof(char*) * channum);
		chans[channum - 1] = token;
	}

	int i, res = POM_OK; // 0
	for (i = 0; i < channum; i++) {
		union irc_cmd_args *cmd_args = malloc(sizeof(union irc_cmd_args));
		memset(cmd_args, 0, sizeof(union irc_cmd_args));
		if (keys && keys[i])
			cmd_args->key = strdup(keys[i]);

		// Queue the join command
		res += target_queue_command_irc(cp, f, chans[i], irc_cmd_join, cmd_args);
	}

	free(chans);
	free(keys);


	return res;
}

static int target_irc_handler_part(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {
	
	char *msg = strchr(args, ' ');
	if (msg) {
		*msg = 0;
		msg = strchr(args, ':');
		if (!msg)
			msg = NULL;
		else
			msg++;
	}

	if (from) { // Someone (or ourself) left a chan we already joined
		struct target_conversation_irc *c = target_get_conv_irc(cp, args, from, f);

		struct target_command_irc *cmd = target_pop_buffered_command(c, irc_cmd_part, NULL);
		if (cmd) {
			if (cmd->args->msg)
				free(cmd->args->msg);
			free(cmd->args);
			free(cmd);

		}

		target_remove_conv_from_nick_irc(from, c);
		int res = target_log_irc(c, &f->tv, "-!- %s [%s] has left %s", from->nick, from->host, args);

		if (cmd) {
			// We found an old command so we can assume that the user left
			target_close_conv_irc(c);
		}
		return res;
	}

	int res = POM_OK;

	char *str, *token, *saveptr = NULL;
	for (str = args; ; str = NULL) {
		token = strtok_r(str, ",", &saveptr);
		if (!token)
			break;

		union irc_cmd_args *cmd_args = malloc(sizeof(union irc_cmd_args));
		memset(cmd_args, 0, sizeof(union irc_cmd_args));
		if (msg)
			cmd_args->msg = strdup(msg);

		// Queue the part command
		res += target_queue_command_irc(cp, f, token, irc_cmd_part, cmd_args);

	}

	return res;
}


static int target_irc_handler_notice(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {
	
	// Find destination(s)
	char *sep = strchr(args, ' ');
	if (!sep) {
		pom_log(POM_LOG_DEBUG "NOTICE without actual message : %s", args);
		return POM_OK;
	}

	*sep = 0;
	do {
		sep++;
	} while (*sep == ' ' || *sep == ':');

	char *conv = args;

	if (!from) { // Message from the client
		if (!is_chan(args)) // If message is not to a chan and not from the client, it's a query with the client
			conv = TARGET_IRC_STATUS_CONV;
		struct target_conversation_irc *c = target_get_conv_irc(cp, conv, NULL, f);
		return target_log_irc(c, &f->tv, "[notice(%s)] %s", args, sep);
	}

	if (!is_chan(from->nick))
		conv = TARGET_IRC_STATUS_CONV; // Notice from users go in the status conv

	struct target_conversation_irc *c = target_get_conv_irc(cp, conv, from, f);

	if (!from->host) // Message from the server
		return target_log_irc(c, &f->tv, "!%s %s", from->nick, sep);

	return target_log_irc(c, &f->tv, "-%s(%s)- %s", from->nick, from->host, sep);

}

static int target_irc_handler_numeric_msg(struct target_conntrack_priv_irc *cp, struct frame *f, unsigned int code, struct target_nick_irc *from, char *args) {

	// First arg is the dest nick
	char *msg = strchr(args, ' ');
	if (!msg) {
		pom_log(POM_LOG_DEBUG "Numeric reply without from");
		return POM_OK;
	}

	*msg = 0;

	do {
		msg++;
	} while (*msg == ' ' || *msg == ':');

	strncpy(cp->nick, args, TARGET_MAX_FROM_IRC);

	// http://wiki.inspircd.org/List_Of_Numerics

	switch (code) {
		case 1: // RPL_WELCOME
		case 2: // RPL_YOURHOST
		case 3: // RPL_CREATED
		case 4: // RPL_MYINFO
		case 5: // RPL_BOUNCE

		case 250: // RPL_STATSCONN
		case 251: // RPL_LUSERCLIENT
		case 252: // RPL_LUSEROP
		case 253: // RPL_LUSERUNKNOWN
		case 254: // RPL_LUSERCHANNELS
		case 255: // RPL_LUSERME

		case 265: // RPL_LOCALUSERS
		case 266: // RPL_GLOBALUSERS

		case 372: // RPL_MOTD
		case 375: // RPL_MOTDSTART
		case 376: // RPL_ENDOFMOTD

		case 396: // RPL_HOSTHIDDEN
			
		{

			struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);
			return target_log_irc(c, &f->tv, "-!- %s", msg);
		}

		case 301: // RPL_AWAY
			return target_irc_handler_rpl_away(cp, f, from, msg);

		case 311: // RPL_WHOISUSER
			return target_irc_handler_rpl_whoisuser(cp, f, from, msg);

		case 312: // RPL_WHOIS_SERVER
			return target_irc_handler_rpl_whoisserver(cp, f, from, msg);

		case 317: // RPL_WHOISIDLE
			return target_irc_handler_rpl_whoisidle(cp, f, from, msg);

		case 318: // RPL_ENDOFWHOIS
			return target_irc_handler_rpl_endofwhois(cp, f, from, msg);

		case 319: // RPL_WHOISCHANNELS
			return target_irc_handler_rpl_whoischannels(cp, f, from, msg);

		case 330: // RPL_WHOISACCOUNT
			return target_irc_handler_rpl_whoisaccount(cp, f, from, msg);

		case 353: // RPL_NAMREPLY
			return target_irc_handler_rpl_namreply(cp, f, from, msg);

		case 366: // RPL_ENDOFNAMES
			return target_irc_handler_rpl_endofnames(cp, f, from, msg);

		case 401: // ERR_NOSUCHNICK
			return target_irc_handler_err_nosuchnick(cp, f, from, msg);

		case 404: // ERR_CANNOTSENDTOCHAN
			return target_irc_handler_err_cannotsendtochan(cp, f, from, msg);

		case 405: // ERR_TOOMANYCHANNELS
		case 471: // ERR_CHANNELISFULL
		case 473: // ERR_INVITEONLYCHAN
		case 474: // ERR_BANNEDFROMCHAN
		case 475: // ERR_BADCHANNELKEY
			return target_irc_handler_join_err(cp, f, from, msg);

		case 501: // ERR_UMODEUNKNOWNFLAG
		case 502: // ERR_USERSDONTMATCH
			return target_irc_handler_mode_user_err(cp, f, from, msg);

		case 671: // RPL_WHOISSECURE
			return target_irc_handler_rpl_whoissecure(cp, f, from, msg);
	}

	pom_log(POM_LOG_DEBUG "Unhandled numeric reply : %u \"%s\"", code, msg);

	return POM_OK;

}

static int target_irc_handler_ping(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	if (from)
		pom_log(POM_LOG_DEBUG "PING from server");
	else
		pom_log(POM_LOG_DEBUG "PING from client");
	return POM_OK;
}

static int target_irc_handler_pong(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	if (from)
		pom_log(POM_LOG_DEBUG "PONG from server");
	else
		pom_log(POM_LOG_DEBUG "PONG from client");
	return POM_OK;
}

static int target_irc_handler_quit(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	int res = POM_OK;
	
	char *msg = strchr(args, ':');
	if (msg)
		msg++;

	if (!from) { // Message from the client
		union irc_cmd_args *cmd_args = malloc(sizeof(union irc_cmd_args));
		memset(cmd_args, 0, sizeof(union irc_cmd_args));
		if (msg)
			cmd_args->msg = strdup(msg);
		return target_queue_command_irc(cp, f, TARGET_IRC_STATUS_CONV, irc_cmd_quit, cmd_args);

	} 
	
	struct target_conv_list_irc *l;
	for (l = from->convs; l; l = l->next) {
		if (msg)
			res += target_log_irc(l->conv, &f->tv, "-!- %s [%s] has quit [%s]", from->nick, from->host, msg);
		else
			res += target_log_irc(l->conv, &f->tv, "-!- %s [%s] has quit", from->nick, from->host);
	}

	// Get rid of the user
	while (from->convs) {
		target_remove_conv_from_nick_irc(from, from->convs->conv);
	}

	return res;
}

static int target_irc_handler_rpl_away(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *tmp = strchr(args, ' ');
	if (tmp) {
		*tmp = 0;
		do {
			tmp++;
		} while (*tmp == ' ' || *tmp == ':');
	} 

	struct target_conversation_irc *c = target_get_conv_irc(cp, args, NULL, f);

	if (tmp)
		return target_log_irc(c, &f->tv, "-!- %s is away: %s", args, tmp); 

	return target_log_irc(c, &f->tv, "-!- %s is away", args); 
}

static int target_irc_handler_rpl_whoisuser(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	// First token is nick
	// Second token is user
	// Third is host
	// Then * : <real_name>
	
	char *real_name = strchr(args, '*');
	if (real_name) {
		do {
			real_name++;
		} while (*real_name == ' ' || *real_name == ':');
	}

	char *nick = NULL, *user = NULL, *host = NULL;

	int toknum = 0;
	char *str, *token, *saveptr = NULL;
	for (str = args; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		toknum++;

		switch (toknum) {
			case 1:
				nick = token;
				break;
			case 2:
				user = token;
				break;
			case 3:
				host = token;
				break;
		}
		if (toknum >= 3)
			break;
	}



	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);
	int res = POM_OK;
	res += target_log_irc(c, &f->tv, "-!- %s [%s@%s]", nick, user, host);
	if (real_name)
		res+= target_log_irc(c, &f->tv, "-!-  ircname  : %s", real_name);

	return res;
}

static int target_irc_handler_rpl_whoisserver(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	// First token nick
	// Second, server
	// Third, server info

	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);
	char *server = strchr(args, ' ');
	if (!server) {
		pom_log(POM_LOG_DEBUG "RPL_WHOISSERVER without server name");
		return POM_OK;
	}

	do {
		server++;
	} while (*server == ' ');

	char *info = strchr(server, ' ');

	if (info) {
		*info = 0;
		do {
			info++;
		} while (*info == ' ' || *info == ':');
		return target_log_irc(c, &f->tv, "-!-  server   : %s [%s]", server, info);
	}

	return target_log_irc(c, &f->tv, "-!-  server   : %s", server);

}

static int target_irc_handler_rpl_whoisidle(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);

	// First token is nick

	char *secs = strchr(args, ' ');
	if (!secs) {
		pom_log(POM_LOG_DEBUG "RPL_WHOISIDLE without seconds");
		return POM_OK;
	}
	do {
		secs++;
	} while (*secs == ' ');

	// Two syntax here : either one integer with idle time or a second integer with signon timestamp

	unsigned int idle = 0, signon = 0;
	int count = sscanf(secs, "%u %u", &idle, &signon);
	if (count < 1) {
		pom_log(POM_LOG_DEBUG "Malformed RPL_WHOISIDLE : %s", secs);
		return POM_OK;
	}

	unsigned int ih, im, is;
	is = idle % 60;
	idle /= 60;
	im = idle % 60;
	idle /= 60;
	ih = idle % 24;
	idle /= 24;

	if (count > 1) {
		time_t time_tmp = signon;
		struct tm tmp;
		localtime_r(&time_tmp, &tmp);
		char *format = "%a %b %d %H:%M:%S %Y";

		char signon_outstr[64];
		memset(signon_outstr, 0, sizeof(signon_outstr));
		strftime(signon_outstr, sizeof(signon_outstr) - 1, format, &tmp);

		return target_log_irc(c, &f->tv, "-!-  idle     : %u days %u hours %u mins %u secs [signon: %s]", idle, ih, im, is, signon_outstr);
	}

	return target_log_irc(c, &f->tv, "-!-  idle     : %u days %u hours %u mins %u secs", idle, ih, im, is);
}

static int target_irc_handler_rpl_endofwhois(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *tmp = strchr(args, ':');
	if (tmp)
		args = tmp + 1;

	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);
	return target_log_irc(c, &f->tv, "-!- %s", args);
}

static int target_irc_handler_rpl_whoisaccount(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *tmp = strchr(args, ' ');
	if (!tmp) {
		pom_log(POM_LOG_DEBUG "RPL_WHOISACCOUNT without account");
		return POM_OK;
	}
	do {
		tmp++;
	} while (*tmp == ' ' || *tmp == ':');

	char *end = strchr(tmp, ' ');
	if (end)
		*end = 0;

	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);
	return target_log_irc(c, &f->tv, "-!-  account  : %s", tmp);
}

static int target_irc_handler_rpl_whoischannels(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *tmp = strchr(args, ':');
	if (!tmp) {
		pom_log(POM_LOG_DEBUG "RPL_WHOISCHANNELS without channels");
		return POM_OK;
	}

	do {
		tmp++;
	} while (*tmp == ' ' || *tmp == ':');

	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);
	return target_log_irc(c, &f->tv, "-!-  channels : %s", tmp);
}

static int target_irc_handler_rpl_namreply(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	// Skip channel modes
	if (*args == '@' || *args == '*' || *args == '=') {
		do {
			args++;
		} while (*args == ' ');
	}

	// First token is channel name
	// Second is channel type
	// Subsequents are users
	
	struct target_conversation_irc *c = NULL;

	int toknum = 0;
	char *str, *token, *saveptr = NULL;
	for (str = args; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		toknum++;
		if (toknum == 1) { // Channel name
			c = target_get_conv_irc(cp, token, NULL, f);
			continue;
		} else if (*token == ':') { // Nick list starts with :
			token++;
		}

		if (toknum >= 2) {
			unsigned int mode = 0;
			if (*token == '+') {
				mode = TARGET_NICK_MODE_VOICED_IRC;
				token++;
			} else if (*token == '%') {
				mode = TARGET_NICK_MODE_HALFOP_IRC;
				token++;
			} else if (*token == '@') {
				mode = TARGET_NICK_MODE_OP_IRC;
				token++;
			}
			// Find the right user
			struct target_nick_irc *n;
			for (n = cp->nicks; n; n = n->next) {
				if (!strcasecmp(n->nick, token))
					break;
			}
			// Create users if they aren't known
			if (!n) {
				n = target_add_nick_irc(cp, token, NULL);
			}

			// Add the right channel for the user if not added yet
			struct target_conv_list_irc *cl;
			for (cl = n->convs; cl; cl = cl->next) {
				if (cl->conv == c)
					break;
			}
			if (!cl) {
				target_add_conv_to_nick_irc(n, c);
			}

			// Set the right mode for the user
			if (mode) {
				struct target_nick_list_irc *nl;
				for (nl = c->nicks; nl; nl = nl->next)
					if (nl->nick == n)
						break;

				if (!nl) {
					pom_log(POM_LOG_WARN "Nick %s not found in conversation %s while setting mode", n->nick, c->who);
				} else {
					nl->mode = mode;
				}
			}
		}
	}


	return POM_OK;

}

static int target_irc_handler_rpl_endofnames(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *tmp = strchr(args, ' ');
	if (tmp) {
		*tmp = 0;
	}

	struct target_conversation_irc *c = target_get_conv_irc(cp, args, from, f);
	int res = POM_OK;

	res += target_log_irc(c, &f->tv, "[Users %s]", args);

	// Count the total number of nicks
	struct target_nick_list_irc *nl;
	int nickcount = 0, opcount = 0, halfopcount = 0, voicecount = 0, normalcount = 0;
	for (nl = c->nicks; nl; nl = nl->next) {
		nickcount++;
		switch (nl->mode) {
			case TARGET_NICK_MODE_OP_IRC:
				opcount++;
				break;
			case TARGET_NICK_MODE_HALFOP_IRC:
				halfopcount++;
				break;
			case TARGET_NICK_MODE_VOICED_IRC:
				voicecount++;
				break;
			default:
				normalcount++;
				break;
		}
	}

	// Divide that in 6 columns
	const unsigned int colcount = 6;
	int rowcount = (nickcount / colcount);
	if (nickcount % colcount)
		rowcount++;

	struct target_nick_list_irc **sorted_list = malloc(sizeof(struct target_nick_list_irc *) * rowcount * colcount);
	memset(sorted_list, 0, sizeof(struct target_nick_list_irc *) * rowcount * colcount);


	int mode = 0;

	int pos = 0;
	// Sort the ops first, then halfop, voiced and eventually normal
	for (mode = TARGET_NICK_MODE_OP_IRC; mode >= 0; mode--) {
		
		for (nl = c->nicks; nl; nl = nl->next) {
			if (nl->mode == mode) {
				sorted_list[pos] = nl;
				pos++;
			}
		}
	}

	int x, y;

	// Calculate max size for each column
	unsigned int colsize[colcount];
	memset(colsize, 0,  sizeof(unsigned int) * colcount);

	for (y = 0; y < colcount; y++) {
		for (x = 0; x < rowcount; x++) {
			pos = (y * rowcount) + x;
			if (sorted_list[pos]) {
				int curlen = strlen(sorted_list[pos]->nick->nick);
				if (colsize[y] < curlen)
					colsize[y] = curlen;
			}
		}
	}

	// Calculate absolute buffer size
	int buffsize = 1;
	for (y = 0; y < colcount; y++)
		buffsize += 4 + colsize[y]; // 4 is for '[@] '

	char *buff = malloc(sizeof(char) * buffsize);
	memset(buff, 0, buffsize);

	// Print the array

	for (x = 0; x < rowcount; x++) {
		for (y = 0; y < colcount; y++) {
			pos = (y * rowcount) + x;
			if (sorted_list[pos]) {
				strcat(buff, "[");
				switch (sorted_list[pos]->mode) {
					case TARGET_NICK_MODE_OP_IRC:
						strcat(buff, "@");
						break;
					case TARGET_NICK_MODE_HALFOP_IRC:
						strcat(buff, "%%");
						break;
					case TARGET_NICK_MODE_VOICED_IRC:
						strcat(buff, "+");
						break;
					default:
						strcat(buff, " ");
						break;
				}
				strcat(buff, sorted_list[pos]->nick->nick);
				int i;
				for (i = 0; i < (colsize[y] - strlen(sorted_list[pos]->nick->nick)); i++)
					strcat(buff, " ");
				strcat(buff, "] ");

			}

		}
		res += target_log_irc(c, &f->tv, "%s", buff);
		*buff = 0;
	}

	free(buff);
	free(sorted_list);

	res += target_log_irc(c, &f->tv, "-!- Packet-o-matic: %s: Total of %u nicks [%u ops, %u halfops, %u voices, %u normal]", c->who, nickcount, opcount, halfopcount, voicecount, normalcount);
	return res;
}

static int target_irc_handler_rpl_whoissecure(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *tmp = strchr(args, ':');
	if (!tmp) {
		pom_log(POM_LOG_DEBUG "RPL_WHOISSECURE without message");
		return POM_OK;
	}
	do {
		tmp++;
	} while (*tmp == ' ' || *tmp == ':');

	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, from, f);
	return target_log_irc(c, &f->tv, "-!-           : %s", tmp);
}

static char *target_irc_err_parse_reason(char *msg, char *default_reason) {

	char *tmp = strchr(msg, ':');
	if (tmp) {
		*tmp = 0;
		do {
			tmp++;
		} while (*tmp == ' ');
	} else {
		tmp = default_reason;
	}

	return tmp;
}

static int target_irc_handler_err_nosuchnick(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *tmp = target_irc_err_parse_reason(args, "No such nick or channel");
	
	struct target_conversation_irc *c = target_get_conv_irc(cp, args, NULL, f);

	struct target_command_irc *cmd = c->cmd_buff_head;

	unsigned type = -1;
	if (cmd)
		type = cmd->type;

	// Now get rid of the invalid conversation
	target_close_conv_irc(c);
	
	char *reason = "";

	// 4 commands can generate this error 
	switch (type) {
		case irc_cmd_privmsg:
			reason = "Cannot send message";
			break;
		case irc_cmd_invite:
			reason = "Cannot invite";
			break;
		case irc_cmd_whois:
			reason = "Cannot whois";
			break;
		case irc_cmd_kill:
			reason = "Cannot kill user";
			break;

	}
	
	c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, NULL, f);

	return target_log_irc(c, &f->tv, "-!- %s : %s: %s", reason, args, tmp); 

}

static int target_irc_handler_err_cannotsendtochan(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *reason = target_irc_err_parse_reason(args, "Cannot send to channel");
	
	struct target_conversation_irc *c = target_get_conv_irc(cp, args, NULL, f);
	struct target_command_irc *cmd = target_pop_buffered_command(c, irc_cmd_privmsg, NULL);

	if (cmd) {
		int res = target_log_irc(c, &cmd->ts, "%s : <%s> %s", reason, cmd->conv->cp->nick, cmd->args->msg);
		free(cmd->args->msg);
		free(cmd->args);
		free(cmd);
		return res;
	}

	return target_log_irc(c, &f->tv, "%s", reason); 

}

static int target_irc_handler_join_err(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	char *reason = target_irc_err_parse_reason(args, "Cannot join channel");
	
	struct target_conversation_irc *c = target_get_conv_irc(cp, args, NULL, f);
	struct target_command_irc *cmd = target_pop_buffered_command(c, irc_cmd_privmsg, NULL);

	if (cmd) {
		int res = target_log_irc(c, &cmd->ts, "%s : %s", args, reason);
		if (cmd->args->key)
			free(cmd->args->key);
		free(cmd->args);
		free(cmd);
		return res;
	}

	return target_log_irc(c, &f->tv, "%s", reason); 

}

static int target_irc_handler_mode_user_err(struct target_conntrack_priv_irc *cp, struct frame *f, struct target_nick_irc *from, char *args) {

	while (*args == ':' || *args == ' ')
		args++;

	struct target_conversation_irc *c = target_get_conv_irc(cp, TARGET_IRC_STATUS_CONV, NULL, f);
	struct target_command_irc *cmd = target_pop_buffered_command(c, irc_cmd_privmsg, NULL);

	if (cmd) {
		int res = target_log_irc(c, &cmd->ts, "Cannot set mode %s on %s : %s", cmd->args->mode.modes, cmd->args->mode.what, args);
		free(cmd->args->mode.what);
		free(cmd->args->mode.modes);
		free(cmd->args);
		free(cmd);
		return res;
	}
	
	return target_log_irc(c, &f->tv, "Cannot set user mode : %s", args);
}

static int target_queue_command_irc(struct target_conntrack_priv_irc *cp, struct frame *f, char *conv,  unsigned int type, union irc_cmd_args *args) {

	struct target_conversation_irc *c = target_get_conv_irc(cp, conv, NULL, f);

	if (!c)
		return POM_ERR;
	
	struct target_command_irc *cmd = malloc(sizeof(struct target_command_irc));
	memset(cmd, 0, sizeof(struct target_command_irc));

	cmd->type = type;
	cmd->args = args;
	cmd->conv = c;
	memcpy(&cmd->ts, &f->tv, sizeof(struct timeval));

	cmd->timeout = timer_alloc(cmd, f->input, target_process_expired_commands_irc);
	timer_queue(cmd->timeout, TARGET_CMD_TIMEOUT_IRC);

	// Add the command at the end

	if (!c->cmd_buff_tail) {
		c->cmd_buff_head = cmd;
		c->cmd_buff_tail = cmd;
	} else {
		cmd->prev = c->cmd_buff_tail;
		c->cmd_buff_tail->next = cmd;
		c->cmd_buff_tail = cmd;
	}

	return POM_OK;
}

static int target_process_expired_queries_irc(void *priv) {

	struct target_conversation_irc *c = priv;

	timer_dequeue(c->expiry);
	timer_cleanup(c->expiry);

	c->expiry = NULL;

	// Remove this conversation from all the users
	// (it's supposed to be a query so only one user should match)
	

	struct target_conntrack_priv_irc *cp = c->cp;

	struct target_nick_irc *n;
	for (n = cp->nicks; n; n = n->next) {
		struct target_conv_list_irc *cl;
		for (cl = n->convs; cl; cl = cl->next) {
			if (cl->conv == c) { // remove it
				if (cl->prev) {
					cl->prev->next = cl->next;
				} else {
					n->convs = cl->next;
				}
				if (cl->next)
					cl->next->prev = cl->prev;
				return POM_OK;
			}
		}

	}

	return POM_OK;
}

static int target_process_expired_commands_irc(void *priv) {

	struct target_command_irc *cmd = priv;

	timer_dequeue(cmd->timeout);
	timer_cleanup(cmd->timeout);

	int res = POM_OK;

	switch (cmd->type) {
		case irc_cmd_privmsg:
			res += target_log_irc(cmd->conv, &cmd->ts, "<%s> %s", cmd->conv->cp->nick, cmd->args->msg);
			free(cmd->args->msg);
			break;

		case irc_cmd_nick:
			res += target_log_irc(cmd->conv, &cmd->ts, "-!- Client is now known as %s (was %s)", cmd->args->nick, cmd->conv->cp->nick);
			strncpy(cmd->conv->cp->nick, cmd->args->nick, TARGET_MAX_FROM_IRC);
			free(cmd->args->nick);
			break;

		case irc_cmd_join:
			if (cmd->args->key) {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- %s has joined %s using key \"%s\"", cmd->conv->cp->nick, cmd->conv->who, cmd->args->key);
				free(cmd->args->key);
			} else {
				res = target_log_irc(cmd->conv, &cmd->ts, "-!- %s has joined %s", cmd->conv->cp->nick, cmd->conv->who);
			}
			break;

		case irc_cmd_part:
			if (cmd->args->msg) {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- %s has left %s [%s]", cmd->conv->cp->nick, cmd->conv->who, cmd->args->msg);
				free(cmd->args->msg);
			} else {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- %s has left %s", cmd->conv->cp->nick, cmd->conv->who);
			}
			res += target_close_conv_irc(cmd->conv);
			break;

		case irc_cmd_mode:
			if (!is_chan(cmd->args->mode.what)) { // User set mode for himself
				strncpy(cmd->conv->cp->nick, cmd->args->mode.what, TARGET_MAX_FROM_IRC);
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- Mode change [%s] for user %s", cmd->args->mode.modes, cmd->args->mode.what);
			} else {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- mode/%s [%s] by %s", cmd->args->mode.what, cmd->args->mode.modes, cmd->conv->cp->nick);
			}
			free(cmd->args->mode.what);
			free(cmd->args->mode.modes);
			break;

		case irc_cmd_oper:
			res += target_log_irc(cmd->conv, &cmd->ts, "-!- User logged in with credential %s/%s", cmd->args->oper.user, cmd->args->oper.pass);
			free(cmd->args->oper.user);
			free(cmd->args->oper.pass);
			break;

		case irc_cmd_kick: {

			if (cmd->args->kick.reason) {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- %s was kicked from %s by %s without reason", cmd->args->kick.who, cmd->conv->who, cmd->conv->cp->nick);
				free(cmd->args->kick.reason);
			} else {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- %s was kicked from %s by %s [%s]", cmd->args->kick.who, cmd->conv->who, cmd->conv->cp->nick, cmd->args->kick.reason);
			}

			struct target_nick_irc *n;
			for (n = cmd->conv->cp->nicks; n; n = n->next) {
				if (!strcasecmp(n->nick, cmd->args->kick.who)) {
					target_remove_conv_from_nick_irc(n, cmd->conv);
					break;
				}
			}
			free(cmd->args->kick.who);
			break;
		}

		case irc_cmd_topic:
			if (cmd->args->topic) {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- %s changed the topic of %s to: %s", cmd->conv->cp->nick, cmd->conv->who, cmd->args->topic);
				free(cmd->args->topic);
			} else {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- Topic unset by %s on %s", cmd->conv->cp->nick, cmd->conv->who);
			}
			break;
		case irc_cmd_quit:
			if (cmd->args->msg) {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- %s has quit [%s]", cmd->conv->cp->nick, cmd->args->msg);
				free(cmd->args->msg);
			} else {
				res += target_log_irc(cmd->conv, &cmd->ts, "-!- %s has quit", cmd->conv->cp->nick);
			}
			break;


		default:
			pom_log("Unhandled command type %u", cmd->type);

	}

	if (cmd->args)
		free(cmd->args);

	struct target_conversation_irc *conv = cmd->conv;

	
	// Remove the command from the list

	if (cmd->prev) {
		cmd->prev->next = cmd->next;
	} else {
		conv->cmd_buff_head = cmd->next;
		if (conv->cmd_buff_head)
			conv->cmd_buff_head->prev = NULL;
	}

	if (cmd->next) {
		cmd->next->prev = cmd->prev;
	} else {
		conv->cmd_buff_tail = cmd->prev;
		if (conv->cmd_buff_tail)
			conv->cmd_buff_tail->next = NULL;
	}

	free(cmd);

	if (!conv->cmd_buff_head) {
		struct target_log_buffer_irc *log_buff = conv->log_buff_head;
		// Process all the pending logs
		while (conv->log_buff_head) {
			conv->log_buff_head = log_buff->next;
			res += target_write_log_irc(conv->fd, log_buff->buff, strlen(log_buff->buff));
			free(log_buff->buff);
			free(log_buff);
			log_buff = conv->log_buff_head;
		}
		conv->log_buff_tail = NULL;
	} else {
		struct target_log_buffer_irc *log_buff = conv->log_buff_head;
		while (log_buff && timercmp(&log_buff->ts, &conv->cmd_buff_head->ts, <)) {
			conv->log_buff_head = log_buff->next;
			if (conv->log_buff_head)
				conv->log_buff_head->prev = NULL;
			else
				conv->log_buff_tail = NULL;
				
			res += target_write_log_irc(conv->fd, log_buff->buff, strlen(log_buff->buff));

			free(log_buff->buff);
			free(log_buff);
			log_buff = conv->log_buff_head;	
		}
	}

	return POM_OK;
}

static struct target_conversation_irc* target_get_conv_irc(struct target_conntrack_priv_irc *cp, char *conv, struct target_nick_irc *from, struct frame *f) {

	// Strip spaces
	
	while (*conv == ' ')
		conv++;
	while (strlen(conv) > 1 && conv[strlen(conv) - 1] == ' ')
		conv[strlen(conv) - 1] = 0;


	struct target_conversation_irc *c = NULL;
	for (c = cp->conv; c; c = c->next) {
		if (!strcmp(c->who, conv))
			break;
	}


	if (!c) {

		c = malloc(sizeof(struct target_conversation_irc));
		memset(c, 0, sizeof(struct target_conversation_irc));

		c->who = strdup(conv);
		c->cp = cp;
		c->fd = -1;

		char *safe_conv = strdup(c->who);
		char *slash = NULL;
		while ((slash = strchr(safe_conv, '/')))
			*slash = '_';

		char filename[NAME_MAX + 1];
		char outstr[20];
		memset(outstr, 0, sizeof(outstr));
		// YYYYMMDD-HHMMSS-UUUUUU
		char *format = "-%Y%m%d-%H%M%S-";
		struct tm tmp;
		localtime_r((time_t*)&f->tv.tv_sec, &tmp);
		strftime(outstr, sizeof(outstr) - 1, format, &tmp);

		struct target_priv_irc *priv = c->cp->t->target_priv;

		char *path = PTYPE_STRING_GETVAL(priv->path);
		if (path[strlen(path) - 1] == '/') {
			snprintf(filename, NAME_MAX, "%s%s%s%u.txt", path, safe_conv, outstr, (unsigned int)f->tv.tv_usec);
		} else {
			snprintf(filename, NAME_MAX, "%s/%s%s%u.txt", path, safe_conv, outstr, (unsigned int)f->tv.tv_usec);
		}

		free(safe_conv);
		char final_name[NAME_MAX];
		memset(final_name, 0, NAME_MAX);
		layer_field_parse(f->l, filename, final_name, NAME_MAX - 1);

		c->filename = strdup(final_name);

		c->next = cp->conv;
		if (cp->conv)
			cp->conv->prev = c;
		
		cp->conv = c;

		pom_log(POM_LOG_DEBUG "Conversation %s created", conv);

		if (from) {
			// Add to the conv list of the user
			target_add_conv_to_nick_irc(from, c);

			if (!is_chan(conv) && from->host) { // It's a query, open log file
				format = "%H:%M:%S";
				strftime(outstr, sizeof(outstr) - 1, format, &tmp);
				int res = target_log_irc(c, &f->tv, "%s -!- Starting query with %s [%s]", outstr, from->nick, from->host);
				if (res != POM_OK)
					return NULL;
			}
		}
	} else if (from && from->host)  { // Server messages don't have the host part
		struct target_conv_list_irc *cl = from->convs;
		while (cl) {
			if (cl->conv == c)
				break;
			cl = cl->next;
		}
		if (!cl) {
			target_add_conv_to_nick_irc(from, c);
		}
	}


	if (!is_chan(c->who)) {
		if (!c->expiry) {
			c->expiry = timer_alloc(c, f->input, target_process_expired_queries_irc);
			timer_queue(c->expiry, TARGET_QUERY_TIMEOUT_IRC);
		} else {
			timer_dequeue(c->expiry);
			timer_queue(c->expiry, TARGET_QUERY_TIMEOUT_IRC);
		}

	}


	return c;

}


static int target_write_log_irc(int fd, char *buff, size_t count) {

	while (count > 0) {
		ssize_t res = write(fd, buff, count);
		if (res == -1) {
			char errbuff[256];
			memset(errbuff, 0, sizeof(errbuff));
			strerror_r(errno, errbuff, sizeof(errbuff) - 1);
			pom_log(POM_LOG_ERR "Error while writing to log file : %s", errbuff);
			return POM_ERR;
		}

		buff += res;
		count -= res;
	}

	return POM_OK;

}

static int target_log_irc(struct target_conversation_irc *c, struct timeval *when, const char *format, ...) {

	if (!c || (c->fd == -1 && target_open_log_irc(c) == POM_ERR))
		return POM_ERR;


	char *time_format = "%H:%M:%S";
	char buff[768];
	memset(buff, 0 , sizeof(buff));
	struct tm tmp;
	localtime_r((time_t*)&(when->tv_sec), &tmp);
	strftime(buff, sizeof(buff) - 1, time_format, &tmp);
	strcat(buff, " ");


	va_list arg_list;
	va_start(arg_list, format);
	vsnprintf(buff + strlen(buff), sizeof(buff) - strlen(buff) - 2, format, arg_list);
	va_end(arg_list);

	strcat(buff, "\n");

	// Check if there are commands waiting for this conversation
	if (c->cmd_buff_head) {
		// then buffer this log entry
		struct target_log_buffer_irc *log_buff = malloc(sizeof(struct target_log_buffer_irc));
		memset(log_buff, 0, sizeof(struct target_log_buffer_irc));
		log_buff->buff = strdup(buff);
		log_buff->conv = c;
		memcpy(&log_buff->ts, when, sizeof(struct timeval));

		// Put this entry at the right place
		
		struct target_log_buffer_irc *tmp = c->log_buff_head;

		if (!tmp) { // Buffer empty
			c->log_buff_head = log_buff;
			c->log_buff_tail = log_buff;
			return POM_OK;
		}

		while (tmp && timercmp(&tmp->ts, when, <))
			tmp = tmp->next;

		if (!tmp) {
			// Reached the end of the list
			c->log_buff_tail->next = log_buff;
			log_buff->prev = c->log_buff_tail;
			c->log_buff_tail = log_buff;
			return POM_OK;
		}

		if (!tmp->prev) { 
			// First item, let see if it goes before or after
			if (timercmp(&tmp->ts, when, >)) {
				// It goes first
				tmp->prev = log_buff;
				log_buff->next = tmp;
				c->log_buff_head = log_buff;
				return POM_OK;
			}
		}

		log_buff->prev = tmp;
		
		if (tmp->next) {
			log_buff->next = tmp->next;
			tmp->next->prev = log_buff;
		} else {
			c->log_buff_tail = log_buff;
		}
		tmp->next = log_buff;
		

		return POM_OK;
	}

	if (target_write_log_irc(c->fd, buff, strlen(buff)) != POM_OK)
		return POM_ERR;


	return POM_OK;
}

static int target_open_log_irc(struct target_conversation_irc *c) {

	if (c->fd != -1)
		return POM_OK;

	c->fd = target_file_open(NULL, c->filename, O_WRONLY | O_CREAT, 0666);

	if (c->fd == -1) {
		char errbuff[256];
		memset(errbuff, 0, sizeof(errbuff));
		strerror_r(errno, errbuff, sizeof(errbuff) - 1);
		pom_log(POM_LOG_ERR "Could not open conversation file %s : %s", c->filename, errbuff);
		return POM_ERR;
	}
	
	pom_log("Log file %s opened", c->filename);

	return POM_OK;
}

static int target_add_conv_to_nick_irc(struct target_nick_irc *n, struct target_conversation_irc *conv) {

	int res = POM_OK;

	// Add the nick to the conversation in alphabetical order
	struct target_nick_list_irc *nl;
	for (nl = conv->nicks; nl; nl = nl->next) {
		if (nl->nick == n)
			break;
	}

	if (!nl) {
		nl = malloc(sizeof(struct target_nick_list_irc));
		memset(nl, 0, sizeof(struct target_nick_list_irc));
		nl->nick = n;

		struct target_nick_list_irc *prevtmp = NULL, *tmp = conv->nicks;
		while (tmp && strcasecmp(tmp->nick->nick, n->nick) < 0) {
			prevtmp = tmp;
			tmp = tmp->next;
		}
		
		if (tmp) { // We stopped somewhere in the list
			if (tmp->prev) { // Add it before this one
				tmp->prev->next = nl;
				nl->prev = tmp->prev;
				tmp->prev = nl;
				nl->next = tmp;
			} else { // Must be the first
				nl->next = conv->nicks;
				conv->nicks = nl;
				if (nl->next)
					nl->next->prev = nl;
			}
		} else {
			if (prevtmp) { // We reached the end
				prevtmp->next = nl;
				nl->prev = prevtmp;
			} else { // First in the list
				conv->nicks = nl;
			}
		}
	} else {
		pom_log(POM_LOG_WARN "Nick %s already in nick list of conversation %s", n->nick, conv->who);
		res = POM_ERR;
	}

	// Add the conversation to the nick
	
	struct target_conv_list_irc *cl;
	for (cl = n->convs; cl; cl = cl->next) {
		if (cl->conv == conv)
			break;
	}

	if (!cl) {
		cl = malloc(sizeof(struct target_conv_list_irc));
		memset(cl, 0, sizeof(struct target_conv_list_irc));
		cl->conv = conv;
		if (n->convs) {
			cl->next = n->convs;
			n->convs->prev = cl;
		}
		n->convs = cl;

	} else {
		pom_log(POM_LOG_WARN "Conversation %s already in conv list of nick %s", conv->who, n->nick);
		res = POM_ERR;
	}

	if (res == POM_OK)
		pom_log(POM_LOG_DEBUG "Nick %s added to conversation %s", n->nick, conv->who);

	return res;
}

static int target_remove_conv_from_nick_irc(struct target_nick_irc *n, struct target_conversation_irc *conv) {

	int res = POM_OK;

	// Remove conversation from nick
	struct target_conv_list_irc *cl;
	for (cl = n->convs; cl; cl = cl->next) {
		if (cl->conv == conv)
			break;
	}

	if (cl) {
		if (cl->prev) {
			cl->prev->next = cl->next;
		} else {
			n->convs = cl->next;
		}

		if (cl->next) {
			cl->next->prev = cl->prev;
		}

		free(cl);
	} else {
		pom_log(POM_LOG_WARN "Conversation %s not found for nick %s", conv->who, n->nick);
		res = POM_ERR;
	}
	// Remove nick from conversation
	
	struct target_nick_list_irc *nl;
	for (nl = conv->nicks; nl; nl = nl->next) {
		if (nl->nick == n)
			break;
	}

	if (nl) {
		if (nl->prev) {
			nl->prev->next = nl->next;
		} else {
			conv->nicks = nl->next;
		}

		if (nl->next) {
			nl->next->prev = nl->prev;
		}

		free(nl);
		
	} else {
		pom_log(POM_LOG_WARN "Nick %s not found in conversation %s", n->nick, conv->who);
		res = POM_ERR;
	}
	
	if (res == POM_OK)
		pom_log(POM_LOG_DEBUG "Nick %s removed from conversation %s", n->nick, conv->who);

	return res;
}

static int target_close_conv_irc(struct target_conversation_irc *c) {

	// Free the command buffer
	while (c->cmd_buff_head) 
		target_process_expired_commands_irc(c->cmd_buff_head);

	pom_log(POM_LOG_DEBUG "Conversation %s closed", c->who);

	free(c->who);
	free(c->filename);

	if (c->fd != -1)
		close(c->fd);

	if (c->expiry) 
		timer_cleanup(c->expiry);

	if (c->next)
		c->next->prev = c->prev;
	
	if (c->prev) {
		c->prev->next = c->prev;
	} else {
		c->cp->conv = c->next;
		if (c->cp->conv)
			c->cp->conv->prev = NULL;
	}

	free(c);

	return POM_OK;
}

static struct target_command_irc* target_pop_buffered_command(struct target_conversation_irc *c, enum irc_command_type type, union irc_cmd_args *arg) {

	struct target_command_irc *cmd;

	for (cmd = c->cmd_buff_head; cmd; cmd = cmd->next) {
		if (cmd->type == type) {
			if (arg) {
				switch (type) {
					case irc_cmd_nick:
						if (strcmp(cmd->args->nick, arg->nick))
							continue;
						break;
					default:
						break;

				}

			}

			if (cmd->prev) {
				cmd->prev->next = cmd->next;
			} else {
				c->cmd_buff_head = cmd->next;
				if (c->cmd_buff_head)
					c->cmd_buff_head->prev = NULL;
			}

			if (cmd->next) {
				cmd->next->prev = cmd->prev;
			} else {
				c->cmd_buff_tail = cmd->prev;
				if (c->cmd_buff_tail)
					c->cmd_buff_tail->next = NULL;
			}
	
			timer_dequeue(cmd->timeout);
			timer_cleanup(cmd->timeout);
			return cmd;
		}
	}

	return NULL;

}
