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
#include "ptype_uint16.h"
#include "ptype_uint32.h"
#include "ptype_uint64.h"

int target_init_log_http(struct target *t) {


	struct target_priv_http *priv = t->target_priv;

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
				pc = end;
			} else {
				priv->log_flags |= flags[p];
			}
			pc++;
		}

		priv->log_flags |= HTTP_LOG_ENABLED;

	}


	struct datavalue_descr ds_fields[256];
	ds_fields['a'].name = "client_addr";
	ds_fields['a'].type = "string";
	ds_fields['A'].name = "server_addr";
	ds_fields['A'].type = "string";
	ds_fields['b'].name = "reponse_size";
	ds_fields['b'].type = "uint64";
	ds_fields['D'].name = "serv_time_ms";
	ds_fields['D'].type = "uint32";
	ds_fields['f'].name = "filename";
	ds_fields['f'].type = "string";
	ds_fields['H'].name = "request_proto";
	ds_fields['H'].type = "string";
	ds_fields['m'].name = "request_method";
	ds_fields['m'].type = "string";
	ds_fields['p'].name = "server_port";
	ds_fields['p'].type = "uint16";
	ds_fields['P'].name = "password";
	ds_fields['P'].type = "string";
	ds_fields['r'].name = "request_first_line";
	ds_fields['r'].type = "string";
	ds_fields['s'].name = "status";
	ds_fields['s'].type = "uint16";
	ds_fields['t'].name = "request_recvd_time";
	ds_fields['t'].type = "string";
	ds_fields['T'].name = "request_elapsed_time";
	ds_fields['T'].type = "uint32";
	ds_fields['u'].name = "username";
	ds_fields['u'].type = "string";
	ds_fields['U'].name = "url";
	ds_fields['U'].type = "string";
	ds_fields['v'].name = "server_name";
	ds_fields['v'].type = "string";



	char *ds_log_path = PTYPE_STRING_GETVAL(priv->ds_log_path);
	if (strlen(ds_log_path)) {

		struct datavalue_descr *fields = NULL;
		unsigned int fields_num = 0;
	
		char *ds_log_format = PTYPE_STRING_GETVAL(priv->ds_log_format);
		char *pc = ds_log_format;
		while ((pc = strchr(pc, '%'))) {

			unsigned char p = *(pc + 1);

			if (p == '{') {
				// Check validity
				char *end = strchr(pc + 2, '}');
				char *check = strchr(pc + 2, '{');
				if (!end || (check && check < end)) {
					pom_log(POM_LOG_ERR "Invalid ds_log_format : Unterminated \%{");
					if (fields) {
						int i;
						for (i = 0; fields[i].name; i++) {
							free(fields[i].name);
							free(fields[i].type);
						}
						free(fields);
					}
					return POM_ERR;
				}
				char *name_prefix = NULL;
				if (*(end + 1) == 'i')
					name_prefix = "hdr_req_";
				else if (*(end + 1) == 'o')
					name_prefix = "hdr_resp_";

				if (!name_prefix) {
					pom_log(POM_LOG_WARN "Warning, unsupported field type '%%%c' in ds_log_format", *(end + 1));
					pc = end;
					continue;
				}

				fields = realloc(fields, sizeof(struct datavalue_descr) * (fields_num + 2));
				memset(&fields[fields_num + 1], 0, sizeof(struct datavalue_descr));
				int hdr_len = end - pc - 2;
				struct datavalue_descr *field = &fields[fields_num];
				field->name = malloc(strlen(name_prefix) + hdr_len + 1);
				strcpy(field->name, name_prefix);
				int name_len = strlen(field->name);
				int i;
				// Lowercase field name and replace non alpha num char by _
				for (i = 0; i < hdr_len; i++) {
					unsigned char c = *(pc + i + 2);
					if (isalnum(c))
						field->name[name_len + i] = tolower(c);
					else
						field->name[name_len + i] = '_';
				}
				field->name[name_len + i] = 0;

				field->type = malloc(strlen("string") + 1);
				strcpy(field->type, "string");
				fields_num++;

				pc = end;
			} else if (ds_fields[p].name) {
				priv->log_flags |= flags[p];
				fields = realloc(fields, sizeof(struct datavalue_descr) * (fields_num + 2));
				memset(&fields[fields_num + 1], 0, sizeof(struct datavalue_descr));
				struct datavalue_descr *field = &fields[fields_num];
				field->name = malloc(strlen(ds_fields[p].name) + 1);
				strcpy(field->name, ds_fields[p].name);
				field->type = malloc(strlen(ds_fields[p].type) + 1);
				strcpy(field->type, ds_fields[p].type);

				fields_num++;

			} else {
				pom_log(POM_LOG_WARN "Warning, unsupported field type '%%%c' in ds_log_format", p);
			}

			pc++;
		}


		if (fields) {
		
			priv->dset = target_open_dataset(t, TARGET_HTTP_DATASET_LOGS, "HTTP logs", PTYPE_STRING_GETVAL(priv->ds_log_path), fields);

			int i;
			for (i = 0; fields[i].name; i++) {
				free(fields[i].name);
				free(fields[i].type);
			}
			free(fields);

			if (!priv->dset) {
				pom_log(POM_LOG_ERR "Unable to open the dataset for logging");
				return POM_ERR;
			}
		} else {
			pom_log(POM_LOG_WARN "Datastore path provided but no fields found. Nothing will be dumped");
		}
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
					cp->log_info->server_host = ptype_print_val_alloc(l3->fields[i]);
				}
				if ((cp->log_info->log_flags & HTTP_LOG_CLIENT_IP) && !strcmp(field->name, client)) {
					cp->log_info->client_host = ptype_print_val_alloc(l3->fields[i]);
				}
			}

			if (cp->log_info->log_flags & HTTP_LOG_SERVER_PORT) {
				struct match_field_reg *field = match_get_field(lastl->type, i);
				if (!strcmp(field->name, server_port)) {
					if (field->type->type == ptype_get_type("uint16")) { // Make sure port type is ok
						cp->log_info->server_port = PTYPE_UINT16_GETVAL(lastl->fields[i]);
					}
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


	// write to log file

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

				int len = (strlen(value) / 4) * 3 + 1;
				creds_buff = malloc(len);
				memset(creds_buff, 0, len);
				int outlen = base64_decode(creds_buff, value, len);
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

	if (*(PTYPE_STRING_GETVAL(priv->log_file))) {
		while ((pc = strchr(log_format, '%'))) {
			
			int i;

			size_t size = pc - log_format, res;
			while ((res = write(priv->log_fd, log_format, size))) {
				log_format += res;
				size -= res;
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
					memset(buff, 0, sizeof(buff));
					snprintf(buff, sizeof(buff) - 1, "%u", info->server_port);
					output = buff;
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

		size_t size = strlen(log_format), res;
		while ((res = write(priv->log_fd, log_format, size))) {
			log_format += res;
			size -= res;
		}
		write(priv->log_fd, "\n", strlen("\n"));
	}

	// write to the database

	if (info->dset_data) {

		char *ds_log_format = PTYPE_STRING_GETVAL(priv->ds_log_format);
		pc = NULL;

		int i = 0, j;

		while ((pc = strchr(ds_log_format, '%'))) {
			

			unsigned char mod = *(pc + 1);

			if (!mod)
				break;

			switch (mod) {

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
						for (j = 0; j < cp->info.headers_num; j++) {
							if (cp->info.headers[j].type == type && !strcasecmp(value, cp->info.headers[j].name)) {
								PTYPE_STRING_SETVAL(info->dset_data[i].value, cp->info.headers[j].value);
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
					if (info->client_host)
						PTYPE_STRING_SETVAL(info->dset_data[i].value, info->client_host);
					break;

				case 'A':
					if (info->server_host)
						PTYPE_STRING_SETVAL(info->dset_data[i].value, info->server_host);
					break;

				case 'b':
					PTYPE_UINT64_SETVAL(info->dset_data[i].value, cp->info.content_pos);
					break;
					
				case 'D':
					if (info->query_time.tv_sec && info->response_time.tv_sec) {
						struct timeval time_served;
						timersub(&info->response_time, &info->query_time, &time_served);
						unsigned long msec_served = (time_served.tv_sec * 1000000) + time_served.tv_usec;
						PTYPE_UINT32_SETVAL(info->dset_data[i].value, msec_served)
					}
					break;

				case 'f':
					if (info->filename)
						PTYPE_STRING_SETVAL(info->dset_data[i].value, info->filename);
					break;

				case 'H':
					if (info->request_proto)
						PTYPE_STRING_SETVAL(info->dset_data[i].value, info->request_proto);
					break;

				case 'm':
					if (info->request_method)
						PTYPE_STRING_SETVAL(info->dset_data[i].value, info->request_method);
					break;

				case 'p':
					PTYPE_UINT16_SETVAL(info->dset_data[i].value, info->server_port);
					break;

				case 'P':
					if (password)
						PTYPE_STRING_SETVAL(info->dset_data[i].value, password);
					break;

				case 'r':
					if (info->first_line)
						PTYPE_STRING_SETVAL(info->dset_data[i].value, info->first_line);
					break;

				case 's':
					PTYPE_UINT16_SETVAL(info->dset_data[i].value, cp->info.err_code);
					break;

				case 't': 
					if (info->query_time.tv_sec) {
						struct tm tmp;
						localtime_r((time_t*)&info->query_time.tv_sec, &tmp);
						strftime(buff, sizeof(buff) - 1, "%d/%b/%Y:%T %z", &tmp);
						PTYPE_STRING_SETVAL(info->dset_data[i].value, buff);
					} else if (info->response_time.tv_sec) {
						// Should we mark that it was the response time ?
						struct tm tmp;
						localtime_r((time_t*)&info->response_time.tv_sec, &tmp);
						strftime(buff, sizeof(buff) - 1, "%d/%b/%Y:%T %z", &tmp);
						PTYPE_STRING_SETVAL(info->dset_data[i].value, buff);
					}
					break;

				case 'T':
					if (info->query_time.tv_sec && info->response_time.tv_sec) {
						struct timeval time_served;
						timersub(&info->response_time, &info->query_time, &time_served);
						PTYPE_UINT32_SETVAL(info->dset_data[i].value, time_served.tv_sec);
					}
					break;

				case 'u':
					if (user)
						PTYPE_STRING_SETVAL(info->dset_data[i].value, user);
					break;

				case 'U':
					if (info->url)
						PTYPE_STRING_SETVAL(info->dset_data[i].value, info->url);
					break;

				case 'v':
					for (j = 0; j < cp->info.headers_num; j++) {
						if (cp->info.headers[j].type == HTTP_QUERY && !strcasecmp("Host", cp->info.headers[j].name)) {
							PTYPE_STRING_SETVAL(info->dset_data[i].value, cp->info.headers[j].value);
							break;
						}
					}
					
					break;

			}

			ds_log_format = pc + 1;
			i++;

		}

		if (target_write_dataset(priv->dset, info->dset_data) == POM_ERR) {
			pom_log(POM_LOG_ERR "Failed to write logs in the dataset");
			target_cleanup_log_http(cp);
			if (creds_buff)
				free(creds_buff);
			return POM_ERR;
		}
	}


	if (creds_buff)
		free(creds_buff);

	return target_cleanup_log_http(cp);

}

int target_reopen_log_http(struct target *t) {

	struct target_priv_http *priv = t->target_priv;

	if (priv->log_fd != -1) {
		char *log_filename = PTYPE_STRING_GETVAL(priv->log_file);
		pom_log(POM_LOG_DEBUG "Reopening log file %s");
		close(priv->log_fd);
		priv->log_fd = open(log_filename, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
		if (priv->log_fd == -1) {
			pom_log(POM_LOG_ERR "Unable to reopen file %s", log_filename);
			return POM_ERR;
		}

	}

	return POM_OK;
}

int target_cleanup_log_http(struct target_conntrack_priv_http *cp) {

	struct http_log_info *info = cp->log_info;

	if (!info)
		return POM_OK;

	// Free the log info
	
	if (info->server_host)
		free(info->server_host);
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

	if (info->dset_data)
		target_cleanup_dataset_values(info->dset_data);

	free(info);

	cp->log_info = NULL;

	return POM_OK;
}
