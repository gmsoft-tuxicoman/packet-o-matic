/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  target_irc : Dump IRC communication
 *  Copyright (C) 2007 Thomas Gouverneur <wildcat@espix.org>
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

#include "target_irc.h"

#include "ptype_bool.h"
#include "ptype_string.h"


struct target_functions *tf;
unsigned int match_undefined_id;
struct target_mode *mode_dump;


int target_register_irc(struct target_reg *r, struct target_functions *tg_funcs) {

	r->init = target_init_irc;
	r->open = target_open_irc;
	r->process = target_process_irc;
	r->close = target_close_irc;
	r->cleanup = target_cleanup_irc;

	tf = tg_funcs;

	match_undefined_id = (*tf->match_register) ("undefined");

	mode_dump = (*tg_funcs->register_mode) (r->type, "dump", "Dump IRC connection into separate files with irssi-like log format.");

	if (!mode_dump)
		return POM_ERR;

	(*tg_funcs->register_param) (mode_dump, "path", "/tmp", "Path of dumped files");

	return POM_OK;

}


int target_init_irc(struct target *t) {

	struct target_priv_irc *priv = malloc(sizeof(struct target_priv_irc));
	bzero(priv, sizeof(struct target_priv_irc));

	t->target_priv = priv;

	priv->path = (*tf->ptype_alloc) ("string", NULL);

	if (!priv->path) {
		target_cleanup_irc(t);
		return POM_ERR;
	}
	
	(*tf->register_param_value) (t, mode_dump, "path", priv->path);

	return POM_OK;
}

int target_close_irc(struct target *t) {

	struct target_priv_irc *priv = t->target_priv;

	while (priv->ct_privs) {
		(*tf->conntrack_remove_priv) (priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_irc(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

int target_cleanup_irc(struct target *t) {

	struct target_priv_irc *priv = t->target_priv;

	if (priv) {

		(*tf->ptype_cleanup) (priv->path);
		free(priv);
	}

	return POM_OK;
}


int target_open_irc(struct target *t) {

	return POM_OK;
}

int target_process_irc(struct target *t, struct frame *f) {

	struct target_priv_irc *priv = t->target_priv;
	struct layer *lastl = f->l;

	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	if (!f->ce)
		(*tf->conntrack_create_entry) (f);

	struct target_conntrack_priv_irc *cp;

	cp = (*tf->conntrack_get_priv) (t, f->ce);

	if (!cp) { // We need to track all connections

		cp = malloc(sizeof(struct target_conntrack_priv_irc));
		bzero(cp, sizeof(struct target_conntrack_priv_irc));

		/* init open files list and fill it with status */
		cp->ofiles = (struct open_file*) malloc(sizeof(struct open_file));
		cp->ofiles->p = NULL;
		cp->ofiles->n = NULL;
		cp->ofiles->fd = -1;
		strncpy(cp->ofiles->what, "status", MAX_NICK);

		cp->state = IRC_UNKNOWN;
		cp->fd = -1;
		(*tf->conntrack_add_priv) (cp, t, f->ce, target_close_connection_irc);
		cp->ce = f->ce;
		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;
	}
	if (cp->state == IRC_NOMATCH) 
		return POM_OK;

	if (lastl->payload_size == 0) {
		(*tf->pom_log) (POM_LOG_TSHOOT "Payload size == 0\r\n");	
		return POM_OK;
	}

	unsigned int pstart, psize;
	pstart = lastl->payload_start;
	psize = lastl->payload_size;

        char *pload = f->buff + lastl->payload_start;
	int i, lstart = 0;
	for (i=0; i < lastl->payload_size; i++) {
 
		if (!pload[i]) { // non ascii
			(*tf->pom_log) (POM_LOG_TSHOOT "NULL char in IRC packet\r\n");
			return POM_OK;
		}
		
		if (pload[i] == '\n') {
			
			char line[MAX_LINE + 1];
			unsigned int llen;

			memset(line, 0, sizeof(line));

			/* remove \r\n */
			pload[i] = '\0';
			if (pload[i-1] == '\r') pload[i-1] = '\0';
			strncpy(line, pload + lstart, MAX_LINE);
			llen = strlen(line);
			/* parse line received */
			cp->f = f;
			cp->t = t;
			cp->tp = priv;
			parse_msg(cp, line, llen);
			lstart = i + 1;
		}
	}

	return POM_OK;
};

int target_close_connection_irc(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	(*tf->pom_log) (POM_LOG_TSHOOT "Closing connection 0x%lx\r\n", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_irc *cp;
	cp = conntrack_priv;

	remove_all_of(cp->ofiles);
	cp->ofiles = NULL;

	struct target_priv_irc *priv = t->target_priv;

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;


	free(cp);

	return POM_OK;
}


/**
 * Parse the line and execute proper process_* function. 
 */
int     parse_msg(struct target_conntrack_priv_irc *cp,
                  char * line,
		  unsigned int len) {

	int i, ret = POM_OK;
	unsigned int is_srv = 0;
	char 	from[MAX_FROM + 1], 
		args[MAX_LINE + 1], 
		token[MAX_TOK + 1], 
		*pos = NULL, 
		*pos2 = NULL;

	if (!len) return POM_OK; /* empty msg */

	memset(from, 0, sizeof(from));
	memset(args, 0, sizeof(args));
	memset(token, 0, sizeof(token));

	(*tf->pom_log) (POM_LOG_TSHOOT "DEBUG: %s\r\n", line);

	if (*line == ':') {
		is_srv = 1;
		line++;
	}

	if ((pos = strchr(line, ' ')) != NULL) {
		if (is_srv) {
			strncpy(from, line, pos - line);
			pos++;
			if ((pos2 = strchr(pos, ' ')) != NULL) {
				strncpy(token, pos, pos2 - pos);
				strncpy(args, pos2 + 1, MAX_LINE);
			}
		} else {
			strncpy(token, line, pos - line);
			strncpy(args, pos + 1, MAX_LINE);
		}
	} else {
		cp->state = IRC_NOMATCH;
		(*tf->pom_log) (POM_LOG_TSHOOT "DEBUG: Cannot find correct IRC Syntax, avoiding to parse this connection in the future...\r\n");
		return POM_ERR;
	}

	(*tf->pom_log) (POM_LOG_TSHOOT "DEBUG: tok=%s|from=%s\r\n", token, from);

	if (!token) return POM_ERR;

	for (i=0; i < NB_TOKENS; i++) {
		
		if (!strcmp(token, Irc_MSG[i].token)) {

			if (Irc_MSG[i].cb) {
				ret = Irc_MSG[i].cb(cp, is_srv, from, args);
			}
			break;
		}
	}

	return ret;
}


/**
 * Parse and log the MODE command.
 */
int     process_mode(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {
	char	wbuf[MAX_LINE + 64 + 1],
		to[MAX_NICK + 1],
		realfrom[MAX_NICK + 1],
		mode[MAX_LINE],
		*pos = NULL;
	unsigned int len;
	
	memset(wbuf, 0, sizeof(wbuf));
	memset(to, 0, sizeof(to));
	memset(mode, 0, sizeof(mode));
	memset(realfrom, 0, sizeof(realfrom));

	strncpy(realfrom, getNick(from), MAX_NICK);

	if ((pos = strchr(line, ' ')) != NULL) {
		
		strncpy(to, line, pos - line);
		pos++;
		if (*pos == ':') pos++;
		strncpy(mode, pos, MAX_LINE);
	}

	

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "MODE: %s\r\n", line);

	/* log to file */
	if (to[0] == '#') {
		
		len = snprintf(wbuf, MAX_LINE + 64, "[%s] mode/%s [%s] by %s\r\n", 
							       get_time(), 
							       to,
							       mode,
							       (!realfrom[0])?cp->my_nick:realfrom);
	} else {
		len = snprintf(wbuf, MAX_LINE + 64, "[%s] Mode change [%s] for user %s\r\n", 
							       get_time(), 
							       mode,
							       to);
	}
	struct open_file *of = NULL;
	if (to[0] == 0) {
		of = get_of(cp->ofiles, "status"); // junk
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, "status", MAX_NICK);
			add_of(cp->ofiles, of);
		}

	} else {
		of = get_of(cp->ofiles, to);
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, to, MAX_NICK);
			add_of(cp->ofiles, of);
		}
	}		
	if (of->fd == -1) {
		open_of(of, cp);
	}

	write(of->fd, wbuf, len);
	return POM_OK;
}



/**
 * Parse and log the OPER command.
 */
int     process_oper(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {
	char	wbuf[MAX_LINE + 64 + 1],
		login[MAX_NICK + 1],
		pass[MAX_LINE + 1],
		realfrom[MAX_NICK + 1],
		*pos = NULL;
	unsigned int len;
	
	memset(wbuf, 0, sizeof(wbuf));
	memset(login, 0, sizeof(login));
	memset(pass, 0, sizeof(pass));
	memset(realfrom, 0, sizeof(realfrom));

	if (is_srv) line++; /* remove ':' */

	strncpy(realfrom, getNick(from), MAX_NICK);

	if ((pos = strchr(line, ' ')) != NULL) {
		strncpy(login, line, pos++ - line);
		strncpy(pass, pos, MAX_LINE);
	}

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "OPER: %s\r\n", line);

	/* log to file */
	len = snprintf(wbuf, MAX_LINE + 64, "[%s] <%s> logged in as OPER with %s/%s\r\n", 
						       get_time(), 
						       (!realfrom[0])?cp->my_nick:realfrom,
						       login,
						       pass);


	struct open_file *of = NULL;
	of = get_of(cp->ofiles, "status"); // junk
	if (!of) { // create
		of = (struct open_file*) malloc(sizeof(struct open_file));
		of->fd = -1;
		strncpy(of->what, "status", MAX_NICK);
		add_of(cp->ofiles, of);
	}
	if (of->fd == -1) {
		open_of(of, cp);
	}

	write(of->fd, wbuf, len);
	return POM_OK;
}


/**
 * Parse and log the KICK command.
 */
int     process_kick(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {
	char	wbuf[MAX_LINE + 64 + 1],
		channel[MAX_CHANNEL + 1],
		nick[MAX_NICK + 1],
		reason[MAX_LINE + 1],
		realfrom[MAX_NICK + 1],
		*pos = NULL,
		*pos2 = NULL;
	unsigned int len;
	
	memset(wbuf, 0, sizeof(wbuf));
	memset(channel, 0, sizeof(channel));
	memset(nick, 0, sizeof(nick));
	memset(reason, 0, sizeof(reason));
	memset(realfrom, 0, sizeof(realfrom));

	if (is_srv) line++; /* remove ':' */

	strncpy(realfrom, getNick(from), MAX_NICK);

	if ((pos = strchr(line, ' ')) != NULL) {
		strncpy(channel, line, pos++ - line);
		if ((pos2 = strchr(pos, ' ')) != NULL) {
			strncpy(nick, pos, pos2 - pos);
			pos2++;
			if (*pos2 == ':') { // reason
				strncpy(reason, ++pos2, MAX_LINE);
			}
		} else {
			strncpy(nick, pos, MAX_NICK); // no reason for kick
		}
	}

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "KICK: %s\r\n", line);

	/* log to file */
	len = snprintf(wbuf, MAX_LINE + 64, "[%s] <%s> has kicked %s out of %s (%s)\r\n", 
						       get_time(), 
						       (!realfrom[0])?cp->my_nick:realfrom,
						       nick,
						       channel,
						       reason);


	struct open_file *of = NULL;
	if (channel[0] == 0) {
		of = get_of(cp->ofiles, "status"); // junk
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, "status", MAX_NICK);
			add_of(cp->ofiles, of);
		}

	} else {
		of = get_of(cp->ofiles, channel);
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, channel, MAX_NICK);
			add_of(cp->ofiles, of);
		}
	}		
	if (of->fd == -1) {
		open_of(of, cp);
	}

	write(of->fd, wbuf, len);
	return POM_OK;
}


/**
 * Parse and log the TOPIC command.
 */
int     process_topic(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {
	char	wbuf[MAX_LINE + 64 + 1],
		channel[MAX_NICK + 1],
		topic[MAX_LINE + 1],
		realfrom[MAX_NICK + 1],
		*pos = NULL;
	unsigned int len;
	
	memset(wbuf, 0, sizeof(wbuf));
	memset(channel, 0, sizeof(channel));
	memset(topic, 0, sizeof(topic));
	memset(realfrom, 0, sizeof(realfrom));

	if (is_srv) line++; /* remove ':' */

	strncpy(realfrom, getNick(from), MAX_NICK);

	if ((pos = strchr(line, ' ')) != NULL) {
		
		strncpy(channel, line, pos - line);
		pos++;
		if (*pos == ':') {
			strncpy(topic, ++pos, MAX_LINE);
		}
	} else {
		strncpy(channel, line, MAX_CHANNEL);
	}

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "TOPIC: %s\r\n", line);

	/* log to file */
	if (topic[0] == 0) {
		len = snprintf(wbuf, MAX_LINE + 64, "[%s] <%s> requested topic of %s\r\n",
								get_time(),
							       (!realfrom[0])?cp->my_nick:realfrom,
								channel);
	} else {
		len = snprintf(wbuf, MAX_LINE + 64, "[%s] <%s> set topic of %s to be \"%s\"\r\n", 
							       get_time(), 
							       (!realfrom[0])?cp->my_nick:realfrom,
							       channel,
					  		       topic);
	}

	struct open_file *of = NULL;
	if (channel[0] == 0) {
		of = get_of(cp->ofiles, "status"); // junk
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, "status", MAX_NICK);
			add_of(cp->ofiles, of);
		}

	} else {
		of = get_of(cp->ofiles, channel);
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, channel, MAX_NICK);
			add_of(cp->ofiles, of);
		}
	}		
	if (of->fd == -1) {
		open_of(of, cp);
	}

	write(of->fd, wbuf, len);
	return POM_OK;
}



/**
 * Parse and log the NICK command.
 */
int     process_nick(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {
	char	wbuf[MAX_LINE + 64 + 1],
		nick[MAX_NICK + 1],
		oldnick[MAX_NICK + 1],
		realfrom[MAX_NICK + 1];
	unsigned int len;
	
	memset(wbuf, 0, sizeof(wbuf));
	memset(nick, 0, sizeof(nick));
	memset(oldnick, 0, sizeof(oldnick));
	memset(realfrom, 0, sizeof(realfrom));

	if (is_srv) line++; /* remove ':' */

	strncpy(nick, line, MAX_NICK);

	strncpy(realfrom, getNick(from), MAX_NICK);

	if (!is_srv) {

		strncpy(oldnick, cp->my_nick, MAX_NICK);
		memset(cp->my_nick, 0, sizeof(cp->my_nick));
		strncpy(cp->my_nick, nick, MAX_NICK);
	} else {
		strncpy(oldnick, realfrom, MAX_NICK);
	}

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "NICK: %s\r\n", line);

	/* log to file */
	len = snprintf(wbuf, MAX_LINE + 64, "[%s] -!- %s is now known as %s\r\n", 
						       get_time(), 
						       oldnick,
						       nick);

	struct open_file *of = NULL;
	if (oldnick[0] == 0) {
		of = get_of(cp->ofiles, "status"); // junk
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, "status", MAX_NICK);
			add_of(cp->ofiles, of);
		}

	} else {
		of = get_of(cp->ofiles, oldnick);
		if (!of) { // create
			of = get_of(cp->ofiles, "status"); // junk
			if (!of) { // create
				of = (struct open_file*) malloc(sizeof(struct open_file));
				of->fd = -1;
				strncpy(of->what, "status", MAX_NICK);
				add_of(cp->ofiles, of);
			}
		}
	}		
	if (of->fd == -1) {
		open_of(of, cp);
	}

	write(of->fd, wbuf, len);
	return POM_OK;
}

/**
 * Parse and log the PASS command.
 */
int     process_pass(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {

	char	wbuf[MAX_LINE + 64 + 1],
		password[MAX_LINE + 1],
		*pos = NULL;
	unsigned int len;

	memset(wbuf, 0, sizeof(wbuf));
	memset(password, 0, sizeof(password));

	if ((pos = strchr(line, ' ')) != NULL) {

		strncpy(password, line, pos - line);
	}

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "PASS : %s\r\n", line);

	/* log to file */
	len = snprintf(wbuf, MAX_LINE + 64, "[%s] password used to connect: %s\r\n", 
						       get_time(), 
						       password);


	struct open_file *of = NULL;
	of = get_of(cp->ofiles, "status"); // junk
	if (!of) { // create
		of = (struct open_file*) malloc(sizeof(struct open_file));
		of->fd = -1;
		strncpy(of->what, "status", MAX_NICK);
		add_of(cp->ofiles, of);
	}
	if (of->fd == -1) {
		open_of(of, cp);
	}

	write(of->fd, wbuf, len);
	return POM_OK;
}


/**
 * Parse and log the JOIN command.
 */
int     process_join(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {
	char	wbuf[MAX_LINE + 64 + 1],
		channel[MAX_CHANNEL + 1],
		password[MAX_LINE + 1],
		realfrom[MAX_NICK + 1],
		*pos = NULL;
	unsigned int len;

	memset(wbuf, 0, sizeof(wbuf));
	memset(channel, 0, sizeof(channel));
	memset(password, 0, sizeof(password));
	memset(realfrom, 0, sizeof(realfrom));

	/* find channel */
	if ((pos = strchr(line, ' ')) != NULL) {
		if (is_srv) line++;
		strncpy(channel, line, pos - line);
		if (strlen(pos+1) > 1) {
			strncpy(password, pos+1, MAX_LINE);
		}
	} else {
		if (is_srv) line++;
		strncpy(channel, line, MAX_CHANNEL); /* no part reason */
	}

	pos = strchr(from, '!');
	if (pos) {
		pos++;
	} else {
		pos = realfrom;
	}

	strncpy(realfrom, getNick(from), MAX_NICK);

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "JOIN from %s: %s\r\n", realfrom, line);

	/* log to file */
	len = snprintf(wbuf, MAX_LINE + 64, "[%s] -!- %s [%s] has joined %s [%s]\r\n", 
						       get_time(), 
						       (!realfrom[0])?cp->my_nick:realfrom,
						       	pos,
						       channel,
						       password);

	struct open_file *of = NULL;
	if (channel[0] == 0) {
		of = get_of(cp->ofiles, "status"); // junk
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, "status", MAX_NICK);
			add_of(cp->ofiles, of);
		}

	} else {
		of = get_of(cp->ofiles, channel);
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, channel, MAX_NICK);
			add_of(cp->ofiles, of);
		}
	}		
	if (of->fd == -1) {
		open_of(of, cp);
	}

	write(of->fd, wbuf, len);

	return POM_OK;
}

/**
 * Parse and log the PART command.
 */
int     process_part(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {
	char 	wbuf[MAX_LINE + 64 + 1],
		channel[MAX_CHANNEL + 1],
		reason[MAX_LINE + 1],
		realfrom[MAX_NICK + 1],
		*pos = NULL;
	unsigned int len;

	memset(wbuf, 0, sizeof(wbuf));
	memset(channel, 0, sizeof(channel));
	memset(reason, 0, sizeof(reason));
	memset(realfrom, 0, sizeof(realfrom));

	/* find channel */
	if ((pos = strchr(line, ' ')) != NULL) {
		strncpy(channel, line, pos - line);
		pos++;
		if (*pos == ':') {
			strncpy(reason, ++pos, MAX_LINE);
		}
	} else {
		strncpy(channel, line, MAX_CHANNEL); /* no part reason */
	}

	strncpy(realfrom, getNick(from), MAX_NICK);

	pos = strchr(from, '!');
	if (pos) {
		pos++;
	} else {
		pos = realfrom;
	}

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "PART from %s: %s\r\n", realfrom, line);

	/* log to file */
	len = snprintf(wbuf, MAX_LINE + 64, "[%s] -!- %s [%s] has left %s [%s]\r\n", get_time(), 
						       (!realfrom[0])?cp->my_nick:realfrom,
						       pos,
						       channel,
						       reason);
	struct open_file *of = NULL;
	if (channel[0] == 0) {
		of = get_of(cp->ofiles, "status"); // junk
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, "status", MAX_NICK);
			add_of(cp->ofiles, of);
		}

	} else {
		of = get_of(cp->ofiles, channel);
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, channel, MAX_NICK);
			add_of(cp->ofiles, of);
		}
	}		
	if (of->fd == -1) {
		open_of(of, cp);
	}

	write(of->fd, wbuf, len);

	return POM_OK;
}

/**
 * Parse and log the NOTICE command.
 */
int     process_notice(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {
	
	char 	wbuf[MAX_LINE + 64 + 1], 
		to[MAX_NICK + 1],
		realfrom[MAX_NICK + 1],
		msg[MAX_LINE + 1],
		*pos = NULL;
	int len;

	memset(wbuf, 0, sizeof(wbuf));
	memset(to, 0, sizeof(to));
	memset(msg, 0, sizeof(msg));
	memset(realfrom, 0, sizeof(realfrom));


	/* find destination of msg */
	if ((pos = strchr(line, ' ')) != NULL) {
		strncpy(to, line, pos - line);
	}
	pos++;
	if (*pos == ':') {
		strncpy(msg, ++pos, MAX_LINE);
	}

	strncpy(realfrom, getNick(from), MAX_NICK);

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "NOTICE from %s: %s\r\n", realfrom, line);

	/* log to file */
	len = snprintf(wbuf, MAX_LINE + 64, "[%s] -%s:%s- %s\r\n", get_time(), 
						       (!realfrom[0])?cp->my_nick:realfrom,
						       to,
						       msg);
	struct open_file *of = NULL;
	if (to[0] == 0) {
		of = get_of(cp->ofiles, "status"); // junk
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, "status", MAX_NICK);
			add_of(cp->ofiles, of);
		}

	} else {
		of = get_of(cp->ofiles, to);
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, to, MAX_NICK);
			add_of(cp->ofiles, of);
		}
	}		
	if (of->fd == -1) {
		open_of(of, cp);
	}

	write(of->fd, wbuf, len);

	return POM_OK;
}

/**
 * Parse and log the PRIVMSG command.
 */
int     process_privmsg(struct target_conntrack_priv_irc *cp,
			unsigned int is_srv,
			char *from,
			char *line) {
	
	char 	wbuf[MAX_LINE + 64 + 1], 
		to[MAX_NICK + 1],
		realfrom[MAX_NICK + 1],
		msg[MAX_LINE + 1],
		*pos = NULL;
	int len;
	
	memset(wbuf, 0, sizeof(wbuf));
	memset(to, 0, sizeof(to));
	memset(msg, 0, sizeof(msg));
	memset(realfrom, 0, sizeof(realfrom));

	(*tf->pom_log) (POM_LOG_TSHOOT "PRIVMSG\r\n");

	/* find destination of msg */
	if ((pos = strchr(line, ' ')) != NULL) {
		strncpy(to, line, pos - line);
	}
	pos++;
	if (*pos == ':') {
		strncpy(msg, ++pos, MAX_LINE);
	}

	strncpy(realfrom, getNick(from), MAX_NICK);

	/* log internally */
	(*tf->pom_log) (POM_LOG_TSHOOT "PRIVMSG from %s: %s\r\n", realfrom, line);

	/* log to file */
	len = snprintf(wbuf, MAX_LINE + 64, "[%s] <%s> %s\r\n", get_time(), 
						       (!realfrom[0])?cp->my_nick:realfrom,
						       msg);

	struct open_file *of = NULL;
	if (to[0] == 0) {
		of = get_of(cp->ofiles, "status"); // junk
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, "status", MAX_NICK);
			add_of(cp->ofiles, of);
		}

	} else {
		of = get_of(cp->ofiles, to);
		if (!of) { // create
			of = (struct open_file*) malloc(sizeof(struct open_file));
			of->fd = -1;
			strncpy(of->what, to, MAX_NICK);
			add_of(cp->ofiles, of);
		}
	}		
	if (of->fd == -1) {
		open_of(of, cp);
	}

        write(of->fd, wbuf, len);

	return POM_OK;
}


/**
 * split nickname from nick!ident@host
 * to be only nick.
 */
char *getNick(char *nick) {

	static char ret[MAX_NICK + 1];
	char * pos;
	memset(ret, 0, sizeof(ret));
	if ((pos = strchr(nick, '!')) != NULL) {
		strncpy(ret, nick, pos - nick);
	} else {
		strncpy(ret, nick, MAX_NICK);
	}
	return ret;
}

/**
 * Get timestamp with HH:MM:SS format
 */
char*	get_time(void) {

	static char out[32];
	char *format = "%H:%M:%S";
	struct tm *tmp;
	time_t ti;
	out[0] = 0;
	ti = time(NULL);
	tmp = localtime(&ti);
	strftime(out, 20, format, tmp);

	return &out[0];
}

/**
 * Get timestamp with format YYYYMMDD-HH:MM:SS
 */
char*	get_timestamp(void) {

	static char out[32];
	char *format = "%Y%m%d-%H:%M:%S";
	struct tm *tmp;
	time_t ti;
	out[0] = 0;
	ti = time(NULL);
	tmp = localtime(&ti);
	strftime(out, 20, format, tmp);

	return &out[0];
}

/**
 * Management for the List of opened files:
 */

/**
 * Add a struct open_file to the list i
 */
int add_of(struct open_file *first, struct open_file *el) {

	if (!first)
		return POM_ERR;

	while(first->n) first = first->n;
	first->n = el;
	el->p = first;
	el->n = NULL;
	return POM_OK;
}

/**
 * Empty the list
 * (warning: the first element has to be assigned with NULL
 * after the execution of this function)
 */
int remove_all_of(struct open_file *first) {
	struct open_file *tmp,*tmp2;
	if (!first)
		return POM_ERR;
	tmp = first;
	do {
		tmp2 = tmp;
		if (tmp->fd) 
			close(tmp->fd);

		tmp = tmp->n;
		free(tmp2);

	} while(tmp);
	return POM_OK;
}

/**
 * Delete an element of the list
 * (warning: can never delete the first one (status))
 */
int del_of(struct open_file *first, const char *what) {

	struct open_file *tmp;

	if (!first)
		return POM_ERR;

	do {
		if (!strncmp(first->what, what, MAX_NICK)) {
			
			if (first->fd != -1) {
				close(first->fd);
			}
			tmp = first;
			if (first->p)
				first->p->n = first->n;
			if (first->n)
				first->n->p = first->p;
			free(tmp);
			
			return POM_OK;
		}
		first = first->n;

	} while (first);

	return POM_OK;
}

/**
 * Find and return an opened file.
 */
struct open_file *get_of(struct open_file *first, const char* what) {

	if (!first)
		return NULL;

	do {
		if (!strncmp(first->what, what, MAX_NICK)) {
			return first;
		}
		first = first->n;

	} while (first);
	return NULL;
}

/**
 * Open the file descriptor of the struct open_file
 */
int open_of(struct open_file *of, struct target_conntrack_priv_irc *cp) {

	char filename[NAME_MAX];
	strcpy(filename, PTYPE_STRING_GETVAL(cp->tp->path));
	strcat(filename, "/");
	strcat(filename, of->what);
	strcat(filename, "-");
	strcat(filename, get_timestamp());
	strcat(filename, ".irc");
	of->fd = (*tf->file_open) (cp->f->l, filename, O_RDWR | O_CREAT, 0666);

	if (of->fd == -1) {
		char errbuff[256];
		strerror_r(errno, errbuff, 256);
		(*tf->pom_log) (POM_LOG_ERR "Unable to open file %s for writing : %s\r\n", filename, errbuff);
		return POM_ERR;
	}

	(*tf->pom_log) (POM_LOG_TSHOOT "%s opened\r\n", filename);

	return POM_OK;

}


