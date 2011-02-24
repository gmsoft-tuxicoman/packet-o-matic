/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2008-2010 Guy Martin <gmsoft@tuxicoman.be>
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
#include "ptype_uint16.h"
#include "ptype_string.h"
#include "ptype_timestamp.h"

static unsigned int match_undefined_id;
static struct target_mode *mode_default;

static unsigned long long total_delivery = 0; ///< Used in mail filename to avoid duplicate

static struct datavalue_descr dataset_fields[7] = {
	{ "time", "timestamp" },
	{ "client", "string" },
	{ "server", "string" },
	{ "port", "uint16" },
	{ "user", "string" },
	{ "password", "string" },
	{ NULL, NULL },
};

enum pop_cmd {
	pop_cmd_other = 0,
	pop_cmd_user,
	pop_cmd_pass,
	pop_cmd_retr,
	pop_cmd_retr_maybe,
	pop_cmd_multiline,
};

int target_register_pop(struct target_reg *r) {

	r->init = target_init_pop;
	r->open = target_open_pop;
	r->process = target_process_pop;
	r->close = target_close_pop;
	r->cleanup = target_cleanup_pop;

	match_undefined_id = match_register("undefined");


	mode_default = target_register_mode(r->type, "dump", "Dump emails into separate maildir folders");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "datastore_path", "", "Path to the datastore");
	target_register_param(mode_default, "path", "/tmp/", "Path of the maildir folder used to save the emails");

	return POM_OK;

}

static int target_init_pop(struct target *t) {

	struct target_priv_pop *priv = malloc(sizeof(struct target_priv_pop));
	memset(priv, 0, sizeof(struct target_priv_pop));

	t->target_priv = priv;

	priv->path = ptype_alloc("string", NULL);
	priv->ds_path = ptype_alloc("string", NULL);

	if (!priv->path || !priv->ds_path) {
		target_cleanup_pop(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "path", priv->path);
	target_register_param_value(t, mode_default, "datastore_path", priv->ds_path);

	priv->perf_tot_conn = perf_add_item(t->perfs, "tot_conn", perf_item_type_counter, "Total number of connections handled");
	priv->perf_cur_conn = perf_add_item(t->perfs, "cur_conn", perf_item_type_gauge, "Current number of connections being handled");
	priv->perf_cur_emails = perf_add_item(t->perfs, "cur_emails", perf_item_type_gauge, "Current number of emails being dumped");
	priv->perf_tot_emails = perf_add_item(t->perfs, "tot_emails", perf_item_type_counter, "Total number of emails dumped");
	priv->perf_found_creds = perf_add_item(t->perfs, "found_creds", perf_item_type_counter, "Total number of credentials found");

	return POM_OK;
}

static int target_open_pop(struct target *t) {

	struct target_priv_pop *priv = t->target_priv;

	char *ds_path = PTYPE_STRING_GETVAL(priv->ds_path);

	if (ds_path && strlen(ds_path)) {
		priv->dset = target_open_dataset(t, TARGET_POP_DATASET_CREDENTIAL, "POP credential found", ds_path, dataset_fields);

		if (!priv->dset) {
			pom_log(POM_LOG_ERR "Unable to open the credential dataset");
			return POM_ERR;
		}

	}

	return POM_OK;

}

static int target_close_pop(struct target *t) {

	struct target_priv_pop *priv = t->target_priv;

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_pop(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

static int target_cleanup_pop(struct target *t) {

	struct target_priv_pop *priv = t->target_priv;

	if (priv) {
			
		ptype_cleanup(priv->ds_path);
		ptype_cleanup(priv->path);

		perf_remove_item(t->perfs, priv->perf_tot_conn);
		perf_remove_item(t->perfs, priv->perf_cur_conn);
		perf_remove_item(t->perfs, priv->perf_cur_emails);
		perf_remove_item(t->perfs, priv->perf_tot_emails);
		perf_remove_item(t->perfs, priv->perf_found_creds);
		free(priv);

	}

	return POM_OK;
}



static int target_process_pop(struct target *t, struct frame *f) {

	struct target_priv_pop *priv = t->target_priv;

	struct layer *lastl = f->l;
	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	if (!f->ce)
		if (conntrack_create_entry(f) == POM_ERR)
			return POM_OK;


	struct target_conntrack_priv_pop *cp;

	cp = conntrack_get_target_priv(t, f->ce);

	if (!cp) {


		// New connection
		cp = malloc(sizeof(struct target_conntrack_priv_pop));
		memset(cp, 0, sizeof(struct target_conntrack_priv_pop));
		cp->fd = -1;
		cp->server_dir = CE_DIR_UNK;

		char tmp[NAME_MAX + 1];
		memset(tmp, 0, sizeof(tmp));
		layer_field_parse(f->l, &f->tv, PTYPE_STRING_GETVAL(priv->path), tmp, NAME_MAX);
		cp->parsed_path = malloc(strlen(tmp) + 3);
		strcpy(cp->parsed_path, tmp);
		if (*(cp->parsed_path + strlen(cp->parsed_path) - 1) != '/')
			strcat(cp->parsed_path, "/");

		if (priv->dset)
			cp->logon_data = target_alloc_dataset_values(priv->dset);

		conntrack_add_target_priv(cp, t, f->ce, target_close_connection_pop);

		cp->ce = f->ce;
		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;

		perf_item_val_inc(priv->perf_cur_conn, 1);
		perf_item_val_inc(priv->perf_tot_conn, 1);
	
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
			if (pop_process_line(t, cp, line, linepos, f, lastl) == POM_ERR)
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
		if (pop_process_line(t, cp, line, linepos, f, lastl) == POM_ERR)
			return POM_ERR;


	return POM_OK;
}

static int pop_process_line(struct target *t, struct target_conntrack_priv_pop *cp, char *line, int size, struct frame *f, struct layer *lastl) {

	enum pop_reply {
		pop_reply_unk = 0,
		pop_reply_ok,
		pop_reply_err,
	};

	struct target_priv_pop *priv = t->target_priv;

	int reply = pop_reply_unk;

	// The first message in a POP3 transaction is +OK from the server
	if (cp->server_dir == CE_DIR_UNK) {
		if (!strncasecmp("+OK", line, strlen("+OK"))) {
			cp->server_dir = cp->ce->direction;
			reply = pop_reply_ok;
		} else if (!strncasecmp("-ERR", line, strlen("-ERR"))) {
			cp->server_dir = cp->ce->direction;
			reply = pop_reply_err;
		}

	}

	if (cp->server_dir == cp->ce->direction) {
		if (!strncasecmp("+OK", line, strlen("+OK")) && (*(line + strlen("+OK")) == '\r' || *(line + strlen("+OK")) == ' '))
			reply = pop_reply_ok;
		else if (!strncasecmp("-ERR", line, strlen("-ERR")) && (*(line + strlen("-ERR")) == '\r' || *(line + strlen("-ERR")) == ' '))
			reply = pop_reply_err;

		switch (cp->lastcmd) {
			case pop_cmd_user:
			case pop_cmd_pass:
				if (reply == pop_reply_ok) {
					if (pop_write_login_info(t, cp) == POM_ERR)
						return POM_ERR;
				} else {
					// Login invalid, forget about it
					if (cp->logon_info_str) {
						free(cp->logon_info_str);
						cp->logon_info_str = NULL;
					}
					cp->logon_got_pass = 0;
				}

				cp->lastcmd = pop_cmd_other;
				break;

			case pop_cmd_retr_maybe:
				if (!strncmp(".\r\n", line, strlen(".\r\n")) || reply != pop_reply_unk) {
					cp->lastcmd = pop_cmd_other;
					if (cp->fd != -1)
						pop_file_close(priv, cp);
					break;
				}
				if (cp->fd == -1) // We are not getting the +OK now so we have to open the file
					if (pop_file_open(priv, cp, &f->tv) == POM_ERR)
						return POM_ERR;

			case pop_cmd_retr:
				if (!strncmp(".\r\n", line, strlen(".\r\n"))) {
					cp->lastcmd = pop_cmd_other;
					pop_file_close(priv, cp);
					break;
				}

				if (cp->fd == -1) { // No file opened, open one
					if (pop_file_open(priv, cp, &f->tv) == POM_ERR)
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
						pop_process_line(t, cp, line, size, f, lastl);
					}
				
				} else
					cp->lastcmd = pop_cmd_other;

		}


	} else {
		// Direction is client or unknown
		int len = 0;

		if (cp->server_dir == CE_DIR_UNK) // We don't know the direction, reset command to see if this is client direction
			cp->lastcmd = pop_cmd_other;

		// trim white spaces
		while (*line && *line == ' ') {
			line++;
			size--;
		}

		if (!strncasecmp("USER", line, strlen("USER"))) {
			len = strlen(line + strlen("USER "));
			char *username = line + strlen("USER ");
			char *end = strchr(username, '\r');
			if (!end)
				end = strchr(username, '\n');

			if (end)
				*end = 0;

			cp->lastcmd = pop_cmd_user;

			// save the time and other stuff
			char strformat[32];
			char *format = "%Y-%m-%d %H:%M:%S";
			struct tm tmp;
			localtime_r((time_t*)&f->tv.tv_sec, &tmp);
			strftime(strformat, sizeof(strformat), format, &tmp);
			
			char *src = NULL, *dst = NULL, *port = NULL;

			int i;
			for (i = 0; i < MAX_LAYER_FIELDS; i++) {
				struct layer *l3 = lastl->prev;
				struct match_field_reg *l4f, *l3f;
				l4f = match_get_field(lastl->type, i);
				l3f = match_get_field(l3->type, i);
				if (!src && !strcmp(l3f->name, "src"))
					src = ptype_print_val_alloc(l3->fields[i]);
				else if (!dst && !strcmp(l3f->name, "dst"))
					dst = ptype_print_val_alloc(l3->fields[i]);
				if (!port && !strcmp(l4f->name, "dport"))
					port = ptype_print_val_alloc(lastl->fields[i]);

				if (src && dst && port)
					break;
			}

			if (!src || !dst || !port) {
				if (src)
					free(src);
				if (dst)
					free(dst);
				if (port)
					free(port);
				pom_log(POM_LOG_ERR "Unable to get all the layer info");
				return POM_ERR;

			}

			if (cp->logon_info_str)
				free(cp->logon_info_str);

			unsigned int len = strlen(strformat) + strlen(", ") +
				strlen(src) + strlen(" -> ") + strlen(dst) + strlen(":") + 5 + // 5 is space for port size (max 65535)
				strlen(" | \"") + strlen(username) + strlen("\", \"");
			cp->logon_info_str = malloc(len + 1);
			snprintf(cp->logon_info_str, len, "%s, %s -> %s:%s | \"%s\", \"", strformat, src, dst, port, username);

			if (cp->logon_data) {
				struct datavalue *dv = cp->logon_data;
				PTYPE_TIMESTAMP_SETVAL(dv[0].value, f->tv.tv_sec);
				PTYPE_STRING_SETVAL_P(dv[1].value, src);
				PTYPE_STRING_SETVAL_P(dv[2].value, dst);
				ptype_parse_val(dv[3].value, port);
				PTYPE_STRING_SETVAL(dv[4].value, username);
			}

			free(port);

		} else if (!strncasecmp("PASS", line, strlen("PASS"))) {

			if (cp->logon_info_str) {
				char *pass = line + strlen("PASS ");
				char *end = strchr(pass, '\r');

				if (!end)
					end = strchr(pass, '\n');

				if (end)
					*end = 0;


				// Record some more useful info
				cp->logon_info_str = realloc(cp->logon_info_str, strlen(cp->logon_info_str) + strlen(pass) + strlen("\"\n") + 1);
				strcat(cp->logon_info_str, pass);
				strcat(cp->logon_info_str, "\"\n");

				if (cp->logon_data)
					PTYPE_STRING_SETVAL(cp->logon_data[5].value, pass);

				cp->logon_got_pass = 1;
			}

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

		if (cp->server_dir == CE_DIR_UNK && cp->lastcmd != pop_cmd_other) {
			if (cp->ce->direction == CE_DIR_FWD)
				cp->server_dir = CE_DIR_REV;
			else if (cp->ce->direction == CE_DIR_REV)
				cp->server_dir = CE_DIR_FWD;
		}


	}

	return POM_OK;
}


static int target_close_connection_pop(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx", (unsigned long) conntrack_priv);

	struct target_priv_pop *priv = t->target_priv;

	struct target_conntrack_priv_pop *cp;
	cp = conntrack_priv;

	if (cp->logon_got_pass)
		pop_write_login_info(t, cp);
	
	if (cp->fd != -1)
		pop_file_close(priv, cp);

	if (cp->logon_info_str)
		free(cp->logon_info_str);
	if (cp->logon_data)
		target_cleanup_dataset_values(cp->logon_data);
	if (cp->parsed_path)
		free(cp->parsed_path);
	if (cp->filename)
		free(cp->filename);

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;

	free(cp);

	perf_item_val_inc(priv->perf_cur_conn, -1);

	return POM_OK;

}

static int pop_file_open(struct target_priv_pop *priv, struct target_conntrack_priv_pop *cp, struct timeval *recvd_time) {

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

	cp->fd = target_file_open(NULL, NULL, final_name, O_RDWR | O_CREAT, 0666);

	if (cp->fd == -1) {
		char errbuff[256];
		strerror_r(errno, errbuff, sizeof(errbuff));
		pom_log(POM_LOG_ERR "Unable to open file %s for writing : %s", filename, errbuff);
		return POM_ERR;
	}

	total_delivery++;

	perf_item_val_inc(priv->perf_cur_emails, 1);

	pom_log(POM_LOG_TSHOOT "%s opened", filename);

	return POM_OK;
}

static int pop_file_close(struct target_priv_pop *priv, struct target_conntrack_priv_pop *cp) {

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
		pom_log(POM_LOG_ERR "Unable to hard link %s with %s", new_name, old_name);
		return POM_ERR;
	}

	if (unlink(old_name) == -1) {
		pom_log(POM_LOG_ERR "Unable to unlink %s", old_name);
		return POM_ERR;
	}

	perf_item_val_inc(priv->perf_cur_emails, -1);
	perf_item_val_inc(priv->perf_tot_emails, 1);

	pom_log(POM_LOG_TSHOOT "%s closed and moved to directory new", old_name);
	return POM_OK;

}

static int pop_write_login_info(struct target *t, struct target_conntrack_priv_pop *cp) {

	struct target_priv_pop *priv = t->target_priv;

	if (!cp->logon_info_str) // No login was captured
		return POM_OK;

	if (!cp->logon_got_pass) { // Password wasn't captured
		free(cp->logon_info_str);
		cp->logon_info_str = NULL;
		return POM_OK;
	}

	if (cp->logon_data) {
		if (target_write_dataset(priv->dset, cp->logon_data) == POM_ERR) {
			pom_log(POM_LOG_ERR "Failed to write credential info in the dataset");
			return POM_ERR;
		}
	}


	char final_name[NAME_MAX + 1];
	memset(final_name, 0, sizeof(final_name));
	strcpy(final_name, cp->parsed_path);
	strncat(final_name, "credentials", NAME_MAX - strlen(final_name));

	int fd;
	fd = target_file_open(NULL, NULL, final_name, O_RDWR | O_APPEND | O_CREAT, 0666);
	if (fd == POM_ERR) {
		pom_log(POM_LOG_ERR "Unable to open file %s to write credentials", final_name);
		return POM_ERR;
	}

	size_t wres = 0, pos = 0, size = strlen(cp->logon_info_str);

	while (size > 0) {
		wres = write(fd, cp->logon_info_str + pos, size);
		if (wres == -1) {
			pom_log(POM_LOG_ERR "Error while writing to credential file");
			close(fd);
			return POM_ERR;
		}
		pos += wres;
		size -= wres;
	}
	close(fd);

	free(cp->logon_info_str);
	cp->logon_info_str = NULL;
	cp->logon_got_pass = 0;

	perf_item_val_inc(priv->perf_found_creds, 1);

	return POM_OK;
}
