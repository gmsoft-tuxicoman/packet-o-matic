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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include "target_http_log.h"

#include "ptype_string.h"

int target_init_log_http(struct target_priv_http *priv) {

	uint16_t flags[256];
	memset(flags, 0, sizeof(flags));
	flags['a'] = HTTP_LOG_CLIENT_IP;
	flags['A'] = HTTP_LOG_SERVER_IP;
	flags['D'] = HTTP_LOG_TIME;
	flags['f'] = HTTP_LOG_FILENAME;
	flags['H'] = HTTP_LOG_REQUEST_PROTOCOL;
	flags['m'] = HTTP_LOG_REQUEST_METHOD;
	flags['p'] = HTTP_LOG_SERVER_PORT;
	flags['P'] = HTTP_LOG_CREDENTIALS;
	flags['r'] = HTTP_LOG_FIRST_LINE;
	flags['t'] = HTTP_LOG_TIME;
	flags['T'] = HTTP_LOG_TIME;
	flags['u'] = HTTP_LOG_CREDENTIALS;
	flags['U'] = HTTP_LOG_URL;
	flags['v'] = HTTP_LOG_SERVERNAME;
	flags['V'] = HTTP_LOG_SERVERNAME;

	priv->log_flags = 0;
	priv->log_fd = -1;
	char *log_filename = PTYPE_STRING_GETVAL(priv->log_file);
	if (strlen(log_filename)) {
		
		int fd = open(log_filename, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);

		if (fd == -1) {
			pom_log(POM_LOG_ERR "Unable to open file %s", log_filename);
			return POM_ERR;
		}
		priv->log_fd = fd;

		char *log_format = PTYPE_STRING_GETVAL(priv->log_format);
		char *pc = log_format;
		while ((pc = strchr(pc, '%'))) {
			unsigned char p = *(pc + 1);
			if (p == '%') {
				// Skip % sign
				pc += 1;
			} else if (p == '{') {
				// Check validity
				char *end = strchr(pc + 2, '}');
				char *check = strchr(pc + 2, '{');
				if (!end || (check && check < end)) {
					pom_log(POM_LOG_ERR "Invalid log_format : Unterminated \%{");
					return POM_ERR;
				}
			} else {
				priv->log_flags |= flags[p];
			}
			pc += 1;
		}

		priv->log_flags |= HTTP_LOG_ENABLED;

	}
	return POM_OK;
}

int target_initial_log_http(struct target_conntrack_priv_http *cp, struct frame *f, struct layer *lastl) {

	if (cp->state == HTTP_QUERY && (cp->log_info->log_flags & HTTP_LOG_TIME))
		memcpy(&cp->log_info->query_time, &f->tv, sizeof(struct timeval));

	if (cp->state == HTTP_RESPONSE && (cp->log_info->log_flags & HTTP_LOG_TIME))
		memcpy(&cp->log_info->response_time, &f->tv, sizeof(struct timeval));

	int direction = -1;
	if (cp->log_info->log_flags & HTTP_LOG_CLIENT_IP ||
		cp->log_info->log_flags & HTTP_LOG_SERVER_PORT ||
		cp->log_info->log_flags & HTTP_LOG_SERVER_IP) {
		if (cp->state == HTTP_QUERY)
			direction = 0;
		else
			direction = 1;
	}
	
	if (direction != -1 && !cp->log_info->server_host && !cp->log_info->client_host) {
		struct layer *l3 = lastl->prev;
		
		char *server, *server_port, *client;
		if (direction == 1) {
			server = "src";
			server_port = "sport";
			client = "dst";
		} else {
			server = "dst";
			server_port = "dport";
			client = "src";
		}
		int i;
		for (i = 0; i < MAX_LAYER_FIELDS; i++) {

			if (cp->log_info->log_flags & HTTP_LOG_SERVER_IP || cp->log_info->log_flags & HTTP_LOG_CLIENT_IP) {
				struct match_field_reg *field = match_get_field(l3->type, i);
				if ((cp->log_info->log_flags & HTTP_LOG_SERVER_IP) && !strcmp(field->name, server)) {
					int size, new_size = 64;
					do {
						size = new_size;
						cp->log_info->server_host = realloc(cp->log_info->server_host, size + 1);
						new_size = ptype_print_val(l3->fields[i], cp->log_info->server_host, size);
						new_size = (new_size < 1) ? new_size * 2 : new_size + 1;
					} while (new_size > size);
				}
				if ((cp->log_info->log_flags & HTTP_LOG_CLIENT_IP) && !strcmp(field->name, client)) {
					int size, new_size = 64;
					do {
						size = new_size;
						cp->log_info->client_host = realloc(cp->log_info->client_host, size + 1);
						new_size = ptype_print_val(l3->fields[i], cp->log_info->client_host, size);
						new_size = (new_size < 1) ? new_size * 2 : new_size + 1;
					} while (new_size > size);
				}
			}

			if (cp->log_info->log_flags & HTTP_LOG_SERVER_PORT) {
				struct match_field_reg *field = match_get_field(lastl->type, i);
				if (!strcmp(field->name, server_port)) {
					const int port_num_max_len = 5; // Max port num is 5 char (65535)
					cp->log_info->server_port = malloc(port_num_max_len + 1);
					ptype_print_val(lastl->fields[i], cp->log_info->server_port, port_num_max_len);
				}
			}

			if ((!(cp->log_info->log_flags & HTTP_LOG_CLIENT_IP) || cp->log_info->client_host)
				&& (!(cp->log_info->log_flags & HTTP_LOG_SERVER_IP) || cp->log_info->server_host)
				&& (!(cp->log_info->log_flags & HTTP_LOG_SERVER_PORT) || cp->log_info->server_port))
				break;
		}

	}

	cp->log_info->log_flags |= HTTP_LOG_GOT_SOME;

	return POM_OK;
}

int target_write_log_http(struct target_priv_http *priv, struct target_conntrack_priv_http *cp) {

	struct http_log_info *info = cp->log_info;

	if (!info)
		return POM_OK;

	if (!(info->log_flags & HTTP_LOG_GOT_SOME)) {
		target_cleanup_log_http(cp);
		return POM_OK;
	}

	char *log_format = PTYPE_STRING_GETVAL(priv->log_format);
	char *pc = NULL;

	char buff[1024];


	char *user = NULL, *password = NULL, *creds_buff = NULL;
	if (info->log_flags & HTTP_LOG_CREDENTIALS) {
		int i;
		for (i = 0; i < cp->info.headers_num; i++) {
			if (cp->info.headers[i].type == HTTP_QUERY && !strcasecmp("Authorization", cp->info.headers[i].name)) {
				char *value = cp->info.headers[i].value;
				int j;
				for (j = 0; value[j] && value[j] != ' '; j++)
					value[j] = tolower(value[j]);
				char *basic = strstr(value, "basic");
				if (!basic) // Not basic authentication
					break;
				value = basic + strlen("basic ");
				while (*value == ' ')
					value++;
				while (value[strlen(value)] == ' ')
					value[strlen(value)] = 0;

				int len = (strlen(value) * 3 / 4) + 1;
				creds_buff = malloc(len);
				memset(creds_buff, 0, len);
				int outlen = base64_decode(creds_buff, value);
				if (outlen == POM_ERR) {
					pom_log(POM_LOG_DEBUG "Unable to decode basic auth header value : \"%s\"", cp->info.headers[i].value);
					break;
				}

				char *colon = strchr(creds_buff, ':');
				if (!colon) {
					pom_log(POM_LOG_DEBUG "Unable to parse the basic auth credentials : \"%s\"", creds_buff);
					break;
				}
				user = creds_buff;
				password = colon + 1;
				*colon = 0;
			
				break;
			}
		}
	}
	
	while ((pc = strchr(log_format, '%'))) {
		
		int i;

		int size = pc - log_format;
		if (size > 0) {
			write(priv->log_fd, log_format, size);
			log_format += size;
		}

		char *output = NULL;
		unsigned char mod = *(pc + 1);

		if (!mod)
			break;

		switch (mod) {
			case '%': 
				output = "%";
				break;

			case '{': {
				
				char *end = strchr(pc + 2, '}');
				int len = end - pc - 2;
				char *value = malloc(len + 1);
				memset(value, 0, len + 1);
				memcpy(value, pc + 2, len);

				int type = -1;
				switch (*(end + 1)) {
					case 'i':
						type = HTTP_QUERY;
						break;

					case 'o':
						type = HTTP_RESPONSE;
						break;
			
				}
				if (type != -1) {
					for (i = 0; i < cp->info.headers_num; i++) {
						if (cp->info.headers[i].type == type && !strcasecmp(value, cp->info.headers[i].name)) {
							output = cp->info.headers[i].value;
							break;
						}
					}
					log_format = end;
				} else
					log_format = end - 1;

				free(value);
				
				break;
			}
			
			case 'a':
				output = info->client_host;
				break;

			case 'A':
				output = info->server_host;
				break;

			case 'b':
				if (!cp->info.content_pos)
					break;
			case 'B':
				memset(buff, 0, sizeof(buff));
				snprintf(buff, sizeof(buff) - 1, "%u", cp->info.content_pos);
				output = buff;
				break;
				
			case 'D':
				if (info->query_time.tv_sec && info->response_time.tv_sec) {
					struct timeval time_served;
					timersub(&info->response_time, &info->query_time, &time_served);
					unsigned long msec_served = (time_served.tv_sec * 1000000) + time_served.tv_usec;
					memset(buff, 0, sizeof(buff));
					snprintf(buff, sizeof(buff) - 1, "%lu", msec_served);
					output = buff;
				}
				break;

			case 'f':
				output = info->filename;
				break;

			case 'H':
				output = info->request_proto;
				break;

			case 'm':
				output = info->request_method;
				break;

			case 'p':
				output = info->server_port;
				break;

			case 'P':
				output = password;
				break;

			case 'r': 
				output = info->first_line;
				break;

			case 's':
				snprintf(buff, sizeof(buff), "%u", cp->info.err_code);
				output=buff;
				break;

			case 't': 
				if (info->query_time.tv_sec) {
					struct tm tmp;
					localtime_r((time_t*)&info->query_time.tv_sec, &tmp);
					strftime(buff, sizeof(buff) - 1, "[%d/%b/%Y:%T %z]", &tmp);
					output = buff;
				} else if (info->response_time.tv_sec) {
					// Should we mark that it was the response time ?
					struct tm tmp;
					localtime_r((time_t*)&info->response_time.tv_sec, &tmp);
					strftime(buff, sizeof(buff) - 1, "[%d/%b/%Y:%T %z]", &tmp);
					output = buff;
				}
				break;

			case 'T':
				if (info->query_time.tv_sec && info->response_time.tv_sec) {
					struct timeval time_served;
					timersub(&info->response_time, &info->query_time, &time_served);
					memset(buff, 0, sizeof(buff));
					snprintf(buff, sizeof(buff) - 1, "%lu", time_served.tv_sec);
					output = buff;
				}
				break;

			case 'u':
				output = user;
				break;

			case 'U':
				output = info->url;
				break;

			case 'v':
				for (i = 0; i < cp->info.headers_num; i++) {
					if (cp->info.headers[i].type == HTTP_QUERY && !strcasecmp("Host", cp->info.headers[i].name)) {
						output = cp->info.headers[i].value;
						break;
					}
				}
				
				break;

		}

		if (!output)
			output = "-";

		write(priv->log_fd, output, strlen(output));


		log_format += 2;

	}

	int size = strlen(log_format);
	if (size > 0)
		write(priv->log_fd, log_format, size);
	write(priv->log_fd, "\n", strlen("\n"));

	if (creds_buff)
		free(creds_buff);

	return target_cleanup_log_http(cp);

}

int target_cleanup_log_http(struct target_conntrack_priv_http *cp) {

	struct http_log_info *info = cp->log_info;

	if (!info)
		return POM_OK;

	// Free the log info
	
	if (info->server_host)
		free(info->server_host);
	if (info->server_port)
		free(info->server_port);
	if (info->client_host)
		free(info->client_host);
	if (info->request_proto)
		free(info->request_proto);
	if (info->request_method)
		free(info->request_method);
	if (info->first_line)
		free(info->first_line);
	if (info->url)
		free(info->url);
	if (info->filename)
		free(info->filename);

	free(info);

	cp->log_info = NULL;

	return POM_OK;
}
