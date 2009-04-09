/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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
#include <arpa/inet.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include "target_http.h"
#include "target_http_mime.h"
#include "target_http_log.h"

#include "ptype_bool.h"
#include "ptype_string.h"

static unsigned int match_undefined_id;
static struct target_mode *mode_default;

int target_register_http(struct target_reg *r) {

	r->init = target_init_http;
	r->open = target_open_http;
	r->process = target_process_http;
	r->close = target_close_http;
	r->cleanup = target_cleanup_http;

	match_undefined_id = match_register("undefined");

	mode_default = target_register_mode(r->type, "default", "Dump each HTTP connection's content into separate files");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "prefix", "/tmp/", "Path of dumped files");
#ifdef HAVE_ZLIB
	target_register_param(mode_default, "decompress", "yes", "Decompress the payload or not on the fly");
#endif
	target_register_param(mode_default, "mime_types_db", DATAROOT "/mime_types.db", "Mime types database path");
	target_register_param(mode_default, "log_file", "", "File where to log the queries");
	target_register_param(mode_default, "log_format", "%v %a %u %t \"%r\" %s %b", "Log format");
	target_register_param(mode_default, "ds_log_path", "", "Datastore path for the logs");
	target_register_param(mode_default, "ds_log_format", "%v %a %u %t %r %s %b", "Database log format");
	target_register_param(mode_default, "dump_img", "no", "Dump the images or not");
	target_register_param(mode_default, "dump_vid", "no", "Dump the videos or not");
	target_register_param(mode_default, "dump_snd", "no", "Dump the audio files or not");
	target_register_param(mode_default, "dump_txt", "no", "Dump the text or not");
	target_register_param(mode_default, "dump_bin", "no", "Dump the binary or not");
	target_register_param(mode_default, "dump_doc", "no", "Dump the documents or not");


	return POM_OK;

}


int target_init_http(struct target *t) {

	struct target_priv_http *priv = malloc(sizeof(struct target_priv_http));
	memset(priv, 0, sizeof(struct target_priv_http));

	t->target_priv = priv;

	priv->prefix = ptype_alloc("string", NULL);
#ifdef HAVE_ZLIB
	priv->decompress = ptype_alloc("bool", NULL);
#endif
	priv->mime_types_db = ptype_alloc("string", NULL);
	priv->log_file = ptype_alloc("string", NULL);
	priv->log_format = ptype_alloc("string", NULL);
	priv->ds_log_path = ptype_alloc("string", NULL);
	priv->ds_log_format = ptype_alloc("string", NULL);
	priv->dump_img = ptype_alloc("bool", NULL);
	priv->dump_vid = ptype_alloc("bool", NULL);
	priv->dump_snd = ptype_alloc("bool", NULL);
	priv->dump_txt = ptype_alloc("bool", NULL);
	priv->dump_bin = ptype_alloc("bool", NULL);
	priv->dump_doc = ptype_alloc("bool", NULL);

	if (!priv->prefix ||
#ifdef HAVE_ZLIB
		!priv->decompress ||
#endif
		!priv->mime_types_db ||
		!priv->log_file ||
		!priv->log_format ||
		!priv->ds_log_path ||
		!priv->ds_log_format ||
		!priv->dump_img ||
		!priv->dump_vid ||
		!priv->dump_snd ||
		!priv->dump_txt ||
		!priv->dump_bin ||
		!priv->dump_doc) {
		target_cleanup_http(t);
		return POM_ERR;
	}
	
	target_register_param_value(t, mode_default, "prefix", priv->prefix);
#ifdef HAVE_ZLIB
	target_register_param_value(t, mode_default, "decompress", priv->decompress);
#endif
	target_register_param_value(t, mode_default, "mime_types_db", priv->mime_types_db);
	target_register_param_value(t, mode_default, "log_file", priv->log_file);
	target_register_param_value(t, mode_default, "log_format", priv->log_format);
	target_register_param_value(t, mode_default, "ds_log_path", priv->ds_log_path);
	target_register_param_value(t, mode_default, "ds_log_format", priv->ds_log_format);
	target_register_param_value(t, mode_default, "dump_img", priv->dump_img);
	target_register_param_value(t, mode_default, "dump_vid", priv->dump_vid);
	target_register_param_value(t, mode_default, "dump_snd", priv->dump_snd);
	target_register_param_value(t, mode_default, "dump_txt", priv->dump_txt);
	target_register_param_value(t, mode_default, "dump_bin", priv->dump_bin);
	target_register_param_value(t, mode_default, "dump_doc", priv->dump_doc);


	return POM_OK;
}

int target_close_http(struct target *t) {

	struct target_priv_http *priv = t->target_priv;

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_http(t, priv->ct_privs->ce, priv->ct_privs);
	}

	if (priv->log_fd != -1)
		close(priv->log_fd);

	target_http_mime_types_cleanup_db(priv);

	return POM_OK;
}

int target_cleanup_http(struct target *t) {

	struct target_priv_http *priv = t->target_priv;

	if (priv) {

		ptype_cleanup(priv->prefix);
#ifdef HAVE_ZLIB
		ptype_cleanup(priv->decompress);
#endif
		ptype_cleanup(priv->mime_types_db);
		ptype_cleanup(priv->log_file);
		ptype_cleanup(priv->log_format);
		ptype_cleanup(priv->ds_log_path);
		ptype_cleanup(priv->ds_log_format);
		ptype_cleanup(priv->dump_img);
		ptype_cleanup(priv->dump_vid);
		ptype_cleanup(priv->dump_snd);
		ptype_cleanup(priv->dump_txt);
		ptype_cleanup(priv->dump_bin);
		ptype_cleanup(priv->dump_doc);
		free(priv);
	}

	return POM_OK;
}

int target_open_http(struct target *t) {

	struct target_priv_http *priv = t->target_priv;

	priv->match_mask = 0;

	if (PTYPE_BOOL_GETVAL(priv->dump_img)) // img
		priv->match_mask |= HTTP_MIME_TYPE_IMG;
	if (PTYPE_BOOL_GETVAL(priv->dump_vid)) // vid
		priv->match_mask |= HTTP_MIME_TYPE_VID;
	if (PTYPE_BOOL_GETVAL(priv->dump_snd)) // snd
		priv->match_mask |= HTTP_MIME_TYPE_SND;
	if (PTYPE_BOOL_GETVAL(priv->dump_txt)) // txt
		priv->match_mask |= HTTP_MIME_TYPE_TXT;
	if (PTYPE_BOOL_GETVAL(priv->dump_bin)) // bin
		priv->match_mask |= HTTP_MIME_TYPE_BIN;
	if (PTYPE_BOOL_GETVAL(priv->dump_doc)) // doc
		priv->match_mask |= HTTP_MIME_TYPE_DOC;

	int res = target_init_log_http(t);
	if (res == POM_ERR)
		return POM_ERR;

	res = target_http_mime_types_read_db(priv);

	return res;

}

int target_process_http(struct target *t, struct frame *f) {

	struct target_priv_http *priv = t->target_priv;
	

	struct layer *lastl = f->l;
	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	if (!f->ce)
		if (conntrack_create_entry(f) == POM_ERR)
			return POM_OK;

	struct target_conntrack_priv_http *cp;

	cp = conntrack_get_target_priv(t, f->ce);

	if (!cp) { // We need to track all connections

		cp = malloc(sizeof(struct target_conntrack_priv_http));
		memset(cp, 0, sizeof(struct target_conntrack_priv_http));
		cp->state = HTTP_HEADER;
		cp->fd = -1;
		conntrack_add_target_priv(cp, t, f->ce, target_close_connection_http);

		cp->ce = f->ce;
		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;

	}

	if (cp->state == HTTP_INVALID)
		return POM_OK;

	if (lastl->payload_size == 0)
		return POM_OK;




	size_t pstart, psize;
	pstart = lastl->payload_start;
	psize = lastl->payload_size;

	char *pload = f->buff + lastl->payload_start;

	if (cp->buff) {
		int size = cp->buff_size + psize;
		cp->buff = realloc(cp->buff, size);
		memcpy(cp->buff + cp->buff_size, pload, psize);
		cp->buff_size = size;
		psize = size;
		pload = cp->buff;
	}

	while (psize > 0) {

		if (cp->state == HTTP_INVALID)
			return POM_OK;

		if (cp->state == HTTP_HEADER || cp->state == HTTP_QUERY || cp->state == HTTP_RESPONSE) {

			if (cp->state == HTTP_HEADER) {

				if (!cp->log_info && priv->log_flags) { // We need to log this
					cp->log_info = malloc(sizeof(struct http_log_info));
					memset(cp->log_info, 0, sizeof(struct http_log_info));
					cp->log_info->log_flags = priv->log_flags;
					if (priv->dset)
						cp->log_info->dset_data = target_alloc_dataset_values(priv->dset);
				}
				
				size_t len = target_parse_query_response_http(priv, cp, pload, psize);

				if (len == POM_ERR) {
					target_reset_conntrack_http(cp);
					cp->state = HTTP_INVALID;
					return POM_OK;
				} else if (len == 0) { // Buffer incomplete
					if (psize > HTTP_MAX_HEADER_LINE) {
						pom_log(POM_LOG_TSHOOT "Invalid HTTP query/request : too long");
						target_reset_conntrack_http(cp);
						cp->state = HTTP_INVALID;
						break;
					} else  {
						target_buffer_payload_http(cp, pload, psize);
						return POM_OK;
					}
				}



				if (cp->log_info)
					target_initial_log_http(cp, f, lastl);

				pload += len;
				psize -= len;
			}

			char *nl = memchr(pload, '\n', psize);
			if (!nl) { // Buffer incomplete
				if (psize > HTTP_MAX_HEADER_LINE) {
					pom_log(POM_LOG_TSHOOT "Header too long. Discarding");
					target_reset_conntrack_http(cp);
					cp->state = HTTP_INVALID;
					break;
				} else {
					target_buffer_payload_http(cp, pload, psize);
					return POM_OK;
				}

			}
			int strsize = nl - pload;
			size_t size = strsize + 1;
			if (nl > pload && *(nl - 1) == '\r')
				strsize--;

			if (strsize == 0) {
				pload += size;
				psize -= size;

				if (target_parse_response_headers_http(priv, cp) == POM_ERR) {
					pom_log(POM_LOG_TSHOOT "Invalid HTTP header received. Ignoring connection");
					target_reset_conntrack_http(cp);
					cp->state = HTTP_INVALID;
					break;
				}

				if (cp->state == HTTP_QUERY) {
					if (cp->info.flags & HTTP_FLAG_HAVE_CLEN && cp->info.content_len != 0) {
						cp->state = HTTP_BODY;
						cp->info.content_type = 0; // Make sure the body isn't matched
						continue;
					} else {
						// Wait for the reply
						cp->state = HTTP_HEADER;
						return POM_OK;
					}
				} else if (cp->state == HTTP_RESPONSE) {
					if ((cp->info.err_code >= 100 && cp->info.err_code < 200) || cp->info.err_code == 204 || cp->info.err_code == 304)
						cp->state = HTTP_HEADER; // HTTP RFC specified that those reply don't have a body
					else
						cp->state = HTTP_BODY;
					continue;
				} else {
					pom_log(POM_LOG_TSHOOT "Internal error, invalid state");
					target_reset_conntrack_http(cp);
					cp->state = HTTP_INVALID;
					break;
				}
				continue;
			}

			char *colon = memchr(pload, ':', strsize);
			if (!colon) {
				if (strsize > HTTP_MAX_HEADER_LINE) { // I've never seen a so long buffer name
					pom_log(POM_LOG_TSHOOT "Invalid header line. Discarding connection");
					target_reset_conntrack_http(cp);
					cp->state = HTTP_INVALID;
					break;
				} else {
					target_buffer_payload_http(cp, pload, psize);
					return POM_OK;
				}

			}

			int name_size = colon - pload;
			while (name_size > 0 && pload[name_size - 1] == ' ')
				name_size--;
			if (!name_size) {
				target_reset_conntrack_http(cp);
				pom_log(POM_LOG_TSHOOT "Header name empty");
				cp->state = HTTP_INVALID;
				break;
			}
			cp->info.headers_num++;
			cp->info.headers = realloc(cp->info.headers, sizeof(struct http_header) * cp->info.headers_num);
			cp->info.headers[cp->info.headers_num - 1].name = malloc(name_size + 1);
			memcpy(cp->info.headers[cp->info.headers_num - 1].name, pload, name_size);
			cp->info.headers[cp->info.headers_num - 1].name[name_size] = 0;
			colon++;
			while (*colon && *colon == ' ')
				colon++;
			int value_size = pload + strsize - colon;
			cp->info.headers[cp->info.headers_num - 1].value = malloc(value_size + 1);
			memcpy(cp->info.headers[cp->info.headers_num - 1].value, colon, value_size);
			cp->info.headers[cp->info.headers_num - 1].value[value_size] = 0;
			cp->info.headers[cp->info.headers_num - 1].type = cp->state;

			pload += size;
			psize -= size;
			
		}

		if (cp->info.flags & HTTP_FLAG_HAVE_CLEN && cp->info.content_len == 0) {
			target_write_log_http(priv, cp);
			target_reset_conntrack_http(cp);
			continue;
		}

		if (cp->state == HTTP_BODY) {
			

			size_t size = psize;
			if (cp->info.flags & HTTP_FLAG_HAVE_CLEN) {
				if (cp->info.content_len - cp->info.content_pos < size)
					size = cp->info.content_len - cp->info.content_pos;
			}

			if (cp->info.flags & HTTP_FLAG_CHUNKED) {
				if (cp->info.chunk_len == 0) {
					/// RFC 2616 specifies that Content-Lenght must be ignored if transfer encoding is used
					if (cp->info.flags & HTTP_FLAG_HAVE_CLEN) {
						pom_log(POM_LOG_TSHOOT "Ignoring invalid Content-Length");
						cp->info.flags &= ~HTTP_FLAG_HAVE_CLEN;
					}
					char *crlf = NULL;
					int len = 0;
					do { // skip remaining crlf
						pload += len;
						size -= len;
						psize -= len;
						crlf = memchr(pload, '\n', size);
						if (!crlf)
							break;
						len = crlf - pload + 1;
					} while (len <= 2 && size >= len);

					if (!crlf) {
						if (size < 8) {
							// buffer too short
							target_buffer_payload_http(cp, pload, psize);
							return POM_OK;
						} else {
							pom_log(POM_LOG_TSHOOT "Invalid chunk size : cannot find CRLF");
							target_reset_conntrack_http(cp);
							cp->state = HTTP_INVALID;
							break;
						}
					}
					char num[9];
					int num_size = crlf - pload - 1;
					if (num_size < 9) {
						memcpy(num, pload, num_size);
						num[num_size] = 0;
					} else {
						pom_log(POM_LOG_TSHOOT "Invalid chunk size : too big");
						target_reset_conntrack_http(cp);
						cp->state = HTTP_INVALID;
						break;
					}

					if (sscanf(num, "%x", &cp->info.chunk_len) != 1) {
						pom_log(POM_LOG_TSHOOT "Invalid chunk size : unparsable");
						target_reset_conntrack_http(cp);
						cp->state = HTTP_INVALID;
						break;
					}
					pload += num_size + 2;
					size -= num_size + 2;
					psize -= num_size + 2;
				}
				if (cp->info.chunk_len == 0) {
					target_write_log_http(priv, cp);
					target_reset_conntrack_http(cp);
					if (size > 2) {
						psize -= 2; // add the crlf
						pload += 2;
					} else {
						break; // Ignore the rest of the payload
					}
					continue;
				}

				int remaining = cp->info.chunk_len - cp->info.chunk_pos;
				if (remaining <= size) {
					size = remaining;
					cp->info.chunk_pos = 0;
					cp->info.chunk_len = 0;
				} else {
					cp->info.chunk_pos += size;
				}


			}

			if (size == 0) // Nothing more to process in this packet
				break;
			
			if (priv->mime_types[cp->info.content_type].type & priv->match_mask) { // Should we process the payload ?
#ifdef HAVE_ZLIB
				if ((cp->info.flags & HTTP_FLAG_GZIP || cp->info.flags & HTTP_FLAG_DEFLATE) && PTYPE_BOOL_GETVAL(priv->decompress)) { // same shit, different headers
					if (cp->fd == -1 && target_file_open_http(t, cp, f, 0) == POM_ERR)
						return POM_ERR;
					size_t len = target_process_gzip_http(cp, pload, size);
					if (len == POM_ERR)
						return POM_ERR;
					else if (len == 0) // Was marked as invalid
						return POM_OK;
					pload += len;
					psize -= len;
					size -= len;
					cp->info.content_pos += len;
				} else {

#endif
					if (cp->fd == -1 && target_file_open_http(t, cp, f, (cp->info.flags & HTTP_FLAG_GZIP || cp->info.flags & HTTP_FLAG_DEFLATE)) == POM_ERR)
						return POM_ERR;
					size_t wres = 0;
					while (size > 0) {
						wres = write(cp->fd, pload, size);
						if (wres == -1) {
							pom_log(POM_LOG_ERR "Unable to write into a file");
							return POM_ERR;
						}
						pload += wres;
						size -= wres;
						psize -= wres;
						cp->info.content_pos += wres;
					}
#ifdef HAVE_ZLIB
				}
#endif
			} else {
				pload += size;
				psize -= size;
				cp->info.content_pos += size;
			}


		}
		if (cp->info.flags & HTTP_FLAG_HAVE_CLEN) {
			if (cp->info.content_pos >= cp->info.content_len) {
				target_write_log_http(priv, cp);
				target_reset_conntrack_http(cp);
			}
		}
	}

	if (cp->buff) {
		free(cp->buff);
		cp->buff = NULL;
		cp->buff_size = 0;
	}

	return POM_OK;
}

int target_close_connection_http(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx", (unsigned long) conntrack_priv);

	struct target_priv_http *priv = t->target_priv;

	struct target_conntrack_priv_http *cp;
	cp = conntrack_priv;

	target_write_log_http(priv, cp);
	target_reset_conntrack_http(cp);

	if (cp->buff)
		free(cp->buff);

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;


	free(cp);

	return POM_OK;

}


size_t target_parse_query_response_http(struct target_priv_http *priv, struct target_conntrack_priv_http *cp, char *pload, size_t psize) {

	if (psize < strlen("HTTP/")) 
		return 0; // Buffer incomplete

	size_t hdr_size;
	char *nl = memchr(pload, '\n', psize);
	if (!nl) {
		if (psize > HTTP_MAX_HEADER_LINE) {
			pom_log(POM_LOG_TSHOOT "Header line too big. Ignoring connection");
			return POM_ERR; // There should have been a line return
		} else {
			return 0; // Buffer incomplete
		}
	}
	size_t size = nl - pload;
	hdr_size = size + 1;
	if (size > 1 && *(nl - 1) == '\r')
		size -= 1;

	size_t line_size = size;

	int tok_num = 0;
	char *token = NULL, *tok_end = pload;
	size_t tok_size;
	while (size > 0 && tok_end) {
		token = tok_end;
		tok_end = memchr(token, ' ', size);
		if (tok_end == token) {
			size--;
			token++;
			continue;
		}
	
		if (!tok_end) {
			tok_size = size;
			size = 0;
		} else  {
			tok_size = tok_end - token;
			tok_end++;
			size -= tok_size + 1;
		}
		


		switch (tok_num) {
			case 0:
				if (!strncasecmp(token, "HTTP/", strlen("HTTP/"))) {
					if (cp->log_info && (cp->log_info->log_flags & HTTP_LOG_LOGGED_RESPONSE)) {
						// We got a new response but we already have logging info from a previous one
						// Let's log the previous one and start a new one
						target_write_log_http(priv, cp);
						cp->log_info = malloc(sizeof(struct http_log_info));
						memset(cp->log_info, 0, sizeof(struct http_log_info));
						cp->log_info->log_flags = priv->log_flags | HTTP_LOG_LOGGED_RESPONSE;
					
					}
					cp->state = HTTP_RESPONSE;
					if (cp->log_info && (cp->log_info->log_flags & HTTP_LOG_REQUEST_PROTOCOL)) {
						cp->log_info->request_proto = malloc(tok_size + 1);
						memcpy(cp->log_info->request_proto, token, tok_size);
						cp->log_info->request_proto[tok_size] = 0;
					}
				} else if (!strncasecmp(token, "GET ", strlen("GET ")) || !strncasecmp(token, "POST ", strlen("POST "))) {
					if (cp->info.headers_num > 0) // New query but headers are present -> reset
						target_reset_conntrack_http(cp);

					if (cp->log_info && (cp->log_info->log_flags & HTTP_LOG_LOGGED_RESPONSE)) {
						// We got a new query but we already have logging info from a previous one
						// Let's log the previous one and start a new one
						target_write_log_http(priv, cp);
						cp->log_info = malloc(sizeof(struct http_log_info));
						memset(cp->log_info, 0, sizeof(struct http_log_info));
						cp->log_info->log_flags = priv->log_flags | HTTP_LOG_LOGGED_QUERY;
					
					}
					if (cp->log_info && (cp->log_info->log_flags & HTTP_LOG_REQUEST_METHOD)) {
						cp->log_info->request_method = malloc(tok_size + 1);
						memcpy(cp->log_info->request_method, token, tok_size);
						cp->log_info->request_method[tok_size] = 0;
					}
					cp->state = HTTP_QUERY;
				} else {
					return POM_ERR; // Unhandled stuff that we won't care
				}
				break;
			case 1:
				if (cp->state == HTTP_RESPONSE) {
					if (tok_size > 4)
						return 0;
					char err_num[5];
					memcpy(err_num, token, tok_size);
					err_num[tok_size] = 0;
					if (sscanf(err_num, "%u", &cp->info.err_code) != 1)
						return POM_ERR;
				} else if (cp->state == HTTP_QUERY && cp->log_info && (cp->log_info->log_flags & HTTP_LOG_URL)) {
					cp->log_info->url = malloc(tok_size + 1);
					memcpy(cp->log_info->url, token, tok_size);
					cp->log_info->url[tok_size] = 0;
				}
				break;
			case 2:
				if (cp->state == HTTP_RESPONSE) {
					if (cp->log_info && (cp->log_info->log_flags & HTTP_LOG_REQUEST_PROTOCOL) && !cp->log_info->request_proto) {
						cp->log_info->request_proto = malloc(tok_size + 1);
						memcpy(cp->log_info->request_proto, token, tok_size);
						cp->log_info->request_proto[tok_size] = 0;
					}
				}
				break;

			default:
				break;

		}
		tok_num++;
	}

	if (tok_num < 1) { // Stuff not matched
		pom_log(POM_LOG_TSHOOT "Unable to parse the response/query");
		return POM_ERR;
	}

	if (cp->state == HTTP_QUERY && cp->log_info && (cp->log_info->log_flags & HTTP_LOG_FIRST_LINE)) {
		cp->log_info->first_line = malloc(line_size + 1);
		strncpy(cp->log_info->first_line, pload, line_size);
		cp->log_info->first_line[line_size] = 0;
	}

	return hdr_size;
}

int target_parse_response_headers_http(struct target_priv_http *priv, struct target_conntrack_priv_http *cp) {
	int i;
	for (i = 0; i < cp->info.headers_num; i++) {
		if (!strcasecmp(cp->info.headers[i].name, "Content-Length")) {
			if(sscanf(cp->info.headers[i].value, "%u", &cp->info.content_len) != 1)
				return POM_ERR;
			cp->info.flags |= HTTP_FLAG_HAVE_CLEN;
		} else if (!strcasecmp(cp->info.headers[i].name, "Content-Encoding")) {
			if (!strcasecmp(cp->info.headers[i].value, "gzip"))
				cp->info.flags |= HTTP_FLAG_GZIP;
			if (!strcasecmp(cp->info.headers[i].value, "deflate"))
				cp->info.flags |= HTTP_FLAG_DEFLATE;
		} else if (!strcasecmp(cp->info.headers[i].name, "Content-Type")) {
			// Make sure it's lowercase as some stupid ppl put that uppercase
			int j;
			for (j = 0; j < strlen(cp->info.headers[i].value); j++)
				cp->info.headers[i].value[j] = tolower(cp->info.headers[i].value[j]);
			char *sc = strchr(cp->info.headers[i].value, ';');
			if (sc)
				*sc = 0;

			cp->info.content_type = target_http_mime_type_get_id(priv, cp->info.headers[i].value);

		} else if (!strcasecmp(cp->info.headers[i].name, "Transfer-Encoding")) {
			if (!strcasecmp(cp->info.headers[i].value, "chunked"))
				cp->info.flags |= HTTP_FLAG_CHUNKED;
		}


	}

	return POM_OK;
}

#ifdef HAVE_ZLIB

size_t target_process_gzip_http(struct target_conntrack_priv_http *cp, char *pload, size_t size) {

	if (!cp->info.zbuff) {

		cp->info.zbuff = malloc(sizeof(z_stream));
		memset(cp->info.zbuff, 0, sizeof(z_stream));

		if (cp->info.flags & HTTP_FLAG_GZIP) {
			if (inflateInit2(cp->info.zbuff, 15 + 32) != Z_OK) { // 15, default window bits. 32, magic value to enable header detection
				if (cp->info.zbuff->msg)
					pom_log(POM_LOG_ERR "Unable to init Zlib : %s", cp->info.zbuff->msg);
				else
					pom_log(POM_LOG_ERR "Unable to init Zlib : Unknown error");
				free(cp->info.zbuff);
				cp->info.zbuff = NULL;
				cp->state = HTTP_INVALID;
				return 0;
			}
		} else if (cp->info.flags & HTTP_FLAG_DEFLATE) {

			if (inflateInit2(cp->info.zbuff, -15) != Z_OK) { // Raw content
				if (cp->info.zbuff->msg)
					pom_log(POM_LOG_ERR "Unable to init Zlib : %s", cp->info.zbuff->msg);
				else
					pom_log(POM_LOG_ERR "Unable to init Zlib : Unknown error");
				free(cp->info.zbuff);
				cp->info.zbuff = NULL;
				cp->state = HTTP_INVALID;
				return 0;
			}
			
		}
	}

	cp->info.zbuff->next_in = (unsigned char *) pload;
	cp->info.zbuff->avail_in = size;
	int out_size = size * 2;
	char *buff = malloc(out_size);

	do {
		cp->info.zbuff->next_out = (unsigned char *)buff;
		cp->info.zbuff->avail_out = out_size;
		int res = inflate(cp->info.zbuff, Z_SYNC_FLUSH);
		if (res == Z_OK || res == Z_STREAM_END) {
			size_t wpos = 0, wres = 0, wsize = out_size - cp->info.zbuff->avail_out;
			while (wsize > 0) {
				wres = write(cp->fd, buff + wpos, wsize);
				if (wres == -1) {
					pom_log(POM_LOG_ERR "Unable to write into a file");
					free(buff);
					return POM_ERR;
				}
				wpos += wres;
				wsize -= wres;
					
			}
			if (res == Z_STREAM_END) {
				inflateEnd(cp->info.zbuff);
				free(cp->info.zbuff);
				cp->info.zbuff = NULL;
				break;
			}

		} else {
			char *msg = cp->info.zbuff->msg;
			if (!msg)
				msg = "Unknown error";
			pom_log(POM_LOG_TSHOOT "Error while uncompressing the gzip content : %s", msg);
			cp->state = HTTP_INVALID;
			free(buff);
			if (cp->info.zbuff) {
				inflateEnd(cp->info.zbuff);
				free(cp->info.zbuff);
				cp->info.zbuff = NULL;
			}
			return 0;
		}

	} while (cp->info.zbuff->avail_in);
	free(buff);

	return size;
}

#endif

int target_reset_conntrack_http(struct target_conntrack_priv_http *cp) {

	cp->info.flags = 0;
	if (cp->info.headers) {
		int i;
		for (i = 0; i < cp->info.headers_num; i++) {
			free(cp->info.headers[i].name);
			free(cp->info.headers[i].value);
		}
		free(cp->info.headers);
		cp->info.headers = NULL;
		cp->info.headers_num = 0;
	}


	if (cp->fd != -1) {
		close(cp->fd);
		cp->fd = -1;
	}

#ifdef HAVE_ZLIB
	if (cp->info.zbuff) {
		inflateEnd(cp->info.zbuff);
		free(cp->info.zbuff);
		cp->info.zbuff = NULL;
	}
#endif
	
	cp->info.chunk_len = 0;
	cp->info.chunk_pos = 0;

	cp->info.content_pos = 0;
	cp->info.content_len = 0;
	cp->state = HTTP_HEADER;
	return POM_OK;
}

int target_buffer_payload_http(struct target_conntrack_priv_http *cp, char *pload, size_t psize) {

	if (psize == 0) {
		free(cp->buff);
		cp->buff = NULL;
		cp->buff_size = 0;
		return POM_OK;
	}


	char *new_buff = malloc(psize);
	memcpy(new_buff, pload, psize);
	if (cp->buff)
		free(cp->buff);
	cp->buff = new_buff;
	cp->buff_size = psize;

	return POM_OK;

}

int target_file_open_http(struct target *t, struct target_conntrack_priv_http *cp, struct frame *f, int is_gzip) {

	struct target_priv_http *priv = t->target_priv;

	if (cp->fd != -1)
		return POM_ERR;

	char filename[NAME_MAX];
	memset(filename, 0, NAME_MAX);

	char outstr[20];
	memset(outstr, 0, sizeof(outstr));
	// YYYYMMDD-HHMMSS-UUUUUU
	char *format = "%Y%m%d-%H%M%S-";
	struct tm tmp;
	localtime_r((time_t*)&f->tv.tv_sec, &tmp);

	strftime(outstr, sizeof(outstr), format, &tmp);

	if (is_gzip)
		snprintf(filename, NAME_MAX, "%s%s%u.%s.gz", PTYPE_STRING_GETVAL(priv->prefix), outstr, (unsigned int)f->tv.tv_usec, priv->mime_types[cp->info.content_type].extension);
	else
		snprintf(filename, NAME_MAX, "%s%s%u.%s", PTYPE_STRING_GETVAL(priv->prefix), outstr, (unsigned int)f->tv.tv_usec, priv->mime_types[cp->info.content_type].extension);

	char filename_final[NAME_MAX];
	memset(filename_final, 0, NAME_MAX);

	layer_field_parse(f->l, filename, filename_final, NAME_MAX);

	cp->fd = target_file_open(NULL, filename_final, O_RDWR | O_CREAT, 0666);

	if (cp->fd == -1) {
		char errbuff[256];
		strerror_r(errno, errbuff, sizeof(errbuff));
		pom_log(POM_LOG_ERR "Unable to open file %s for writing : %s", filename, errbuff);
		cp->state = HTTP_INVALID;
		return POM_ERR;
	}

	if (cp->log_info && (cp->log_info->log_flags & HTTP_LOG_FILENAME)) {
		cp->log_info->filename = malloc(strlen(filename_final) + 1);
		strcpy(cp->log_info->filename, filename_final);
	}

	pom_log(POM_LOG_TSHOOT "%s opened", filename);

	return POM_OK;
}


