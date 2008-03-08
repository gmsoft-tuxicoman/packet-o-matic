/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2008 Guy Martin <gmsoft@tuxicoman.be>
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
#include "target_pop.h"

#include "ptype_bool.h"
#include "ptype_string.h"

struct target_functions *tf;

unsigned int match_undefined_id;
struct target_mode *mode_default;

unsigned long long total_delivery = 0; ///< Used in mail filename to avoid duplicate

enum pop_cmd {
	pop_cmd_other = 0,
	pop_cmd_user,
	pop_cmd_pass,
	pop_cmd_retr,
	pop_cmd_retr_maybe,
	pop_cmd_multiline,
};

int target_register_pop(struct target_reg *r, struct target_functions *tg_funcs) {

	r->init = target_init_pop;
	r->process = target_process_pop;
	r->close = target_close_pop;
	r->cleanup = target_cleanup_pop;

	tf = tg_funcs;

	match_undefined_id = (*tf->match_register) ("undefined");

	mode_default = (*tg_funcs->register_mode) (r->type, "dump", "Dump emails into separate maildir folders");

	if (!mode_default)
		return POM_ERR;

	(*tg_funcs->register_param) (mode_default, "path", "/tmp/", "Path of the maildir folder used to save the emails");

	return POM_OK;

}

int target_init_pop(struct target *t) {

	struct target_priv_pop *priv = malloc(sizeof(struct target_priv_pop));
	bzero(priv, sizeof(struct target_priv_pop));

	t->target_priv = priv;

	priv->path = (*tf->ptype_alloc) ("string", NULL);

	if (!priv->path) {
		target_cleanup_pop(t);
		return POM_ERR;
	}

	(*tf->register_param_value) (t, mode_default, "path", priv->path);

	return POM_OK;
}


int target_close_pop(struct target *t) {

	struct target_priv_pop *priv = t->target_priv;

	while (priv->ct_privs) {
		(*tf->conntrack_remove_priv) (priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_pop(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

int target_cleanup_pop(struct target *t) {

	struct target_priv_pop *priv = t->target_priv;

	if (priv) {
			
		(*tf->ptype_cleanup) (priv->path);
		free(priv);

	}

	return POM_OK;
}



int target_process_pop(struct target *t, struct frame *f) {

	struct target_priv_pop *priv = t->target_priv;

	struct layer *lastl = f->l;
	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	if (!f->ce)
		(*tf->conntrack_create_entry) (f);


	struct target_conntrack_priv_pop *cp;

	cp = (*tf->conntrack_get_priv) (t, f->ce);

	if (!cp) {


		// New connection
		cp = malloc(sizeof(struct target_conntrack_priv_pop));
		bzero(cp, sizeof(struct target_conntrack_priv_pop));
		cp->fd = -1;
		cp->server_dir = CE_DIR_UNK;

		char tmp[NAME_MAX + 1];
		memset(tmp, 0, sizeof(tmp));
		(*tf->layer_field_parse) (f->l, PTYPE_STRING_GETVAL(priv->path), tmp, NAME_MAX);
		cp->parsed_path = malloc(strlen(tmp) + 3);
		strcpy(cp->parsed_path, tmp);
		if (*(cp->parsed_path + strlen(cp->parsed_path) - 1) != '/')
			strcat(cp->parsed_path, "/");

		(*tf->conntrack_add_priv) (cp, t, f->ce, target_close_connection_pop);

		cp->ce = f->ce;
		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;
	
	



	}

	if (lastl->payload_size == 0)
		return POM_OK;

	char* payload = f->buff + lastl->payload_start;


	char line[2048];
	memset(line, 0, sizeof(line));
	int bufpos = 0, linepos = 0;
	while (bufpos < lastl->payload_size && linepos < sizeof(line) - 1) {
		line[linepos] = payload[bufpos];
		if (payload[bufpos] == '\n') {
			if (pop_process_line(cp, line, linepos, f) == POM_ERR)
				return POM_ERR;
			memset(line, 0, sizeof(line));
			linepos = 0;
			bufpos++;
			continue;
		}
		bufpos++;
		linepos++;

	}

	if (linepos > 0)
		if (pop_process_line(cp, line, linepos, f) == POM_ERR)
			return POM_ERR;


	return POM_OK;
};

int pop_process_line(struct target_conntrack_priv_pop *cp, char *line, int size, struct frame *f) {

	enum pop_reply {
		pop_reply_unk = 0,
		pop_reply_ok,
		pop_reply_err,
	};


	int reply = pop_reply_unk;

	// The first message in a POP3 transaction is +OK from the server
	if (cp->server_dir == CE_DIR_UNK) {
		if (!strncasecmp("+OK", line, strlen("+OK"))) {
			cp->server_dir = cp->ce->direction;
			reply = pop_reply_ok;
		} else if (!strncasecmp("-ERR", line, strlen("-ERR"))) {
			cp->server_dir = cp->ce->direction;
			reply = pop_reply_err;
		} else 
			return POM_OK;

	}

	// skip space in front of commands sent by client
	while ((*line == ' ' || *line == '\t') && cp->server_dir != cp->ce->direction) {
		line++;
		size--;
	}

	if (cp->server_dir == cp->ce->direction) {
		if (!strncasecmp("+OK", line, strlen("+OK")) && (*(line + strlen("+OK")) == '\r' || *(line + strlen("+OK")) == ' '))
			reply = pop_reply_ok;
		else if (!strncasecmp("-ERR", line, strlen("-ERR")) && (*(line + strlen("-ERR")) == '\r' || *(line + strlen("-ERR")) == ' '))
			reply = pop_reply_err;

		switch (cp->lastcmd) {
			case pop_cmd_user:
			case pop_cmd_pass:
				if (reply == pop_reply_err) {
					if (cp->username) {
						free(cp->username);
						cp->username = NULL;
					}
					if (cp->password) {
						free(cp->password);
						cp->password = NULL;
					}
				} else if (cp->username && cp->password) {
					if (pop_write_login_info(cp, f) == POM_ERR)
						return POM_ERR;
				}
				cp->lastcmd = pop_cmd_other;
				break;

			case pop_cmd_retr_maybe:
				if (!strncmp(".\r\n", line, strlen(".\r\n")) || reply != pop_reply_unk) {
					cp->lastcmd = pop_cmd_other;
					if (cp->fd != -1)
						pop_file_close(cp);
					break;
				}
				if (cp->fd == -1) // We are not getting the +OK now so we have to open the file
					if (pop_file_open(cp, &f->tv) == POM_ERR)
						return POM_ERR;

			case pop_cmd_retr:
				if (!strncmp(".\r\n", line, strlen(".\r\n"))) {
					cp->lastcmd = pop_cmd_other;
					pop_file_close(cp);
					break;
				}

				if (cp->fd == -1) { // No file opened, open one
					if (pop_file_open(cp, &f->tv) == POM_ERR)
						return POM_ERR;
				} else {
					// remove the /r
					if (size > 0 && line[size - 1] == '\r' && line[size] == '\n') {
						line[size] = '\0';
						line[size - 1] = '\n';
					}

					int res, count = 0;
					do {
						res = write(cp->fd, line, size);
						if (res == -1)
							return POM_ERR;
						count += res;
					} while (count < size);
					
				}
				break;
				
			case pop_cmd_multiline:
				if (!strcmp(".\r\n", line))
					cp->lastcmd = pop_cmd_other;
				break;

			default:
				// Now let's catch messages when we don't have client side
				if (reply == pop_reply_unk) {
					unsigned long long lluint;
					unsigned int uint, uint2;
					char useless_buff[64];
					memset(useless_buff, 0, sizeof(useless_buff));
					if (!memcmp(line, "\r\n", strlen("\r\n"))) // ignore empty line
						break;

					if (sscanf(line, "%63s", useless_buff) == 1) {
						int i, is_all_up = 0;
						for (i = 0; i < strlen(useless_buff); i++)
							if (!isupper(useless_buff[i]) && useless_buff[i] != '-') {
								is_all_up++;
								break;
							}
						if (!is_all_up) {
							// looks like CAPA command or alike
							cp->lastcmd = pop_cmd_multiline;
							break;
						}
						
					}
					if (sscanf(line, "%u %u", &uint, &uint2) == 2) {
						// looks like a TOP command
						cp->lastcmd = pop_cmd_multiline;
					} else if (sscanf(line, "%llu %63s", &lluint, useless_buff) == 2) {
						// looks like a UIDL or STAT command
						cp->lastcmd = pop_cmd_multiline;
					} else { // most probably a message :)
						cp->lastcmd = pop_cmd_retr_maybe;
						pop_process_line(cp, line, size, f);
					}
				
				} else
					cp->lastcmd = pop_cmd_other;

		}


	} else {
		int len = 0;
		if (!strncasecmp("USER", line, strlen("USER"))) {
			len = strlen(line + strlen("USER "));
			if (cp->username)
				free(cp->username);
			cp->username = malloc(len + 1);
			strcpy(cp->username, line + strlen("USER "));
			cp->lastcmd = pop_cmd_user;
		} else if (!strncasecmp("PASS", line, strlen("PASS"))) {
			len = strlen(line + strlen("PASS "));
			if (cp->password)
				free(cp->password);
			cp->password = malloc(len + 1);
			strcpy(cp->password, line + strlen("PASS "));
			cp->lastcmd = pop_cmd_pass;
		} else if (!strncasecmp("RETR", line, strlen("RETR"))) {
			cp->lastcmd = pop_cmd_retr;
		} else if (!strncasecmp("STAT", line, strlen("STAT"))) {
			cp->lastcmd = pop_cmd_multiline;
		} else if (!strncasecmp("UIDL", line, strlen("UIDL"))) {
			cp->lastcmd = pop_cmd_multiline;
		} else if (!strncasecmp("TOP", line, strlen("TOP"))) {
			cp->lastcmd = pop_cmd_multiline;
		} else if (!strncasecmp("CAPA", line, strlen("CAPA"))) {
			cp->lastcmd = pop_cmd_multiline;
		}

	}

	return POM_OK;
}


int target_close_connection_pop(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	(*tf->pom_log) (POM_LOG_TSHOOT "Closing connection 0x%lx\r\n", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_pop *cp;
	cp = conntrack_priv;
	
	if (cp->fd != -1)
		pop_file_close(cp);

	if (cp->username)
		free(cp->username);
	if (cp->password)
		free(cp->password);
	if (cp->parsed_path)
		free(cp->parsed_path);
	if (cp->filename)
		free(cp->filename);

	struct target_priv_pop *priv = t->target_priv;

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;

	free(cp);

	return POM_OK;

}

int pop_file_open(struct target_conntrack_priv_pop *cp, struct timeval *recvd_time) {

		char filename[NAME_MAX + 1];
		memset(filename, 0, NAME_MAX + 1);

		sprintf(filename, "%u.M%uP%uQ%llu.", (unsigned int)recvd_time->tv_sec, (unsigned int)recvd_time->tv_usec, getpid(), total_delivery);

		char hostname[HOST_NAME_MAX + 1];
		if (gethostname(hostname, HOST_NAME_MAX) == -1)
			strcpy(hostname, "unknow.host");
		strncat(filename, hostname, NAME_MAX - strlen(filename));

		cp->filename = malloc(strlen(filename) + 1);
		strcpy(cp->filename, filename);

		char final_name[NAME_MAX + 1];

		strncpy(final_name, cp->parsed_path, NAME_MAX);
		strncat(final_name, "tmp/", NAME_MAX - strlen(final_name));
		strncat(final_name, filename, NAME_MAX - strlen(final_name));

		cp->fd = (*tf->file_open) (NULL, final_name, O_RDWR | O_CREAT, 0666);

		if (cp->fd == -1) {
			char errbuff[256];
			strerror_r(errno, errbuff, sizeof(errbuff));
			(*tf->pom_log) (POM_LOG_ERR "Unable to open file %s for writing : %s\r\n", filename, errbuff);
			return POM_ERR;
		}

		total_delivery++;

		(*tf->pom_log) (POM_LOG_TSHOOT "%s opened\r\n", filename);

	return POM_OK;
}

int pop_file_close(struct target_conntrack_priv_pop *cp) {

	if (cp->fd == -1)
		return POM_ERR;
	close(cp->fd);
	cp->fd = -1;


	char old_name[NAME_MAX + 1], new_name[NAME_MAX + 1];
	strncpy(old_name, cp->parsed_path, NAME_MAX);
	strncat(old_name, "tmp/", NAME_MAX - strlen(old_name));
	strncat(old_name, cp->filename, NAME_MAX - strlen(old_name));
	
	char cur_dir[NAME_MAX + 1];
	strcpy(cur_dir, cp->parsed_path);
	strncat(cur_dir, "cur/", NAME_MAX - strlen(cur_dir));
	// Ensure the cur directory exists
	mkdir(cur_dir, 00777);


	strncpy(new_name, cp->parsed_path, NAME_MAX);
	strncat(new_name, "new/", NAME_MAX - strlen(new_name));
	// Maybe the directory new doesn't exists, let's try to create it
	mkdir(new_name, 00777);


	strncat(new_name, cp->filename, NAME_MAX - strlen(new_name));

	free(cp->filename);
	cp->filename = NULL;

	if (link(old_name, new_name) == -1) {
		(*tf->pom_log) (POM_LOG_ERR "Unable to hard link %s with %s\r\n", new_name, old_name);
		return POM_ERR;
	}

	if (unlink(old_name) == -1) {
		(*tf->pom_log) (POM_LOG_ERR "Unable to unlink %s\r\n", old_name);
		return POM_ERR;
	}

	(*tf->pom_log) (POM_LOG_TSHOOT "%s closed and moved to directory new\r\n", old_name);
	return POM_OK;

}

int pop_write_login_info(struct target_conntrack_priv_pop *cp, struct frame *f) {

	char final_name[NAME_MAX + 1];
	memset(final_name, 0, sizeof(final_name));
	strcpy(final_name, cp->parsed_path);
	strncat(final_name, "logins", NAME_MAX - strlen(final_name));


	char line[2048];
	memset(line, 0, sizeof(line));

	char strformat[1024];
	char *format = "%Y-%m-%d %H:%M:%S, ${ipv4.dst} ${ipv6.dst} ${tcp.dport} -> ${ipv4.src} ${ipv6.src} ${tcp.sport}";
	struct tm *tmp;
	tmp = localtime((time_t*)&f->tv.tv_sec);
	strftime(strformat, sizeof(strformat), format, tmp);


	if ((*tf->layer_field_parse) (f->l, strformat, line, sizeof(line)) == POM_ERR) {
		(*tf->pom_log) (POM_LOG_WARN "Internal error while parsing string for target_pop logins\r\n");
		return POM_ERR;
	}
	
	char *end;
	end = strchr(cp->username, '\r');
	*end = 0;
	end = strchr(cp->password, '\r');
	*end = 0;

	strncat(line, " | \"", NAME_MAX - strlen(line));
	strncat(line, cp->username, NAME_MAX - strlen(line));
	strncat(line, "\", \"", NAME_MAX - strlen(line));
	strncat(line, cp->password, NAME_MAX - strlen(line));
	strncat(line, "\"\n", NAME_MAX - strlen(line));
	
	int fd;
	fd = (*tf->file_open) (NULL, final_name, O_RDWR | O_APPEND | O_CREAT, 0666);
	write(fd, line, strlen(line));
	close(fd);




	return POM_OK;
}
