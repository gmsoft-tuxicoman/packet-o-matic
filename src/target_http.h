/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __TARGET_HTTP_H__
#define __TARGET_HTTP_H__


#include "modules_common.h"
#include "rules.h"

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#define HTTP_HEADER	1 ///< Looking for a header
#define HTTP_QUERY	2 ///< This is a query
#define HTTP_RESPONSE	3 ///< This is a response
#define HTTP_BODY	4 ///< Handling the body
#define HTTP_INVALID	9 ///< Invalid HTTP message, will discard the rest of the connection

#define HTTP_FLAG_HAVE_CLEN	0x01
#define HTTP_FLAG_CHUNKED	0x04
#define HTTP_FLAG_GZIP		0x08
#define HTTP_FLAG_DEFLATE	0x10

#define HTTP_GZIP_MAGIC_0	0x1f
#define HTTP_GZIP_MAGIC_1	0x8b
#define HTTP_GZIP_FLAG_HCRC	0x02
#define HTTP_GZIP_FLAG_EXTRA	0x04
#define HTTP_GZIP_FLAG_NAME	0x08
#define HTTP_GZIP_FLAG_COMMENT	0x10

#define MIME_TYPES_HASH_SIZE	0x100

#define HTTP_MAX_HEADER_LINE	4096

#define HTTP_MIME_TYPE_UNK 0x00
#define HTTP_MIME_TYPE_BIN 0x01
#define HTTP_MIME_TYPE_IMG 0x02
#define HTTP_MIME_TYPE_VID 0x04
#define HTTP_MIME_TYPE_SND 0x08
#define HTTP_MIME_TYPE_TXT 0x10
#define HTTP_MIME_TYPE_DOC 0x20

struct http_header {

	char *name;
	char *value;
	int type; // either HTTP_QUERY or HTTP_RESPONSE

};

struct http_mime_type_entry {
	
	char *name;
	char *extension;
	unsigned int type;

};

struct http_mime_type_hash_entry {
	unsigned int id;
	struct http_mime_type_hash_entry *next;
};

struct target_conntrack_priv_info_http {

	struct http_header *headers;
	unsigned int headers_num;
	unsigned int err_code;
	unsigned int content_len, content_pos;
	unsigned int chunk_len, chunk_pos;
	unsigned int content_type; // index in the mime_type array
	unsigned int flags;

#ifdef HAVE_ZLIB
	z_stream *zbuff;
#endif

};

struct target_conntrack_priv_http {

	int fd;
	unsigned int state;
	unsigned int direction;
	char *buff;
	size_t buff_size;
	struct target_conntrack_priv_info_http info;
	struct http_log_info *log_info;

	struct conntrack_entry *ce;
	struct target_conntrack_priv_http *next;
	struct target_conntrack_priv_http *prev;
};


struct target_priv_http {

	int match_mask;

	struct ptype *prefix;
	struct ptype *decompress;
	struct ptype *mime_types_db;
	struct ptype *log_file;
	struct ptype *log_format;
	struct ptype *ds_log_path;
	struct ptype *ds_log_format;
	struct ptype *dump_img;
	struct ptype *dump_vid;
	struct ptype *dump_snd;
	struct ptype *dump_txt;
	struct ptype *dump_bin;
	struct ptype *dump_doc;

	struct http_mime_type_entry *mime_types;
	unsigned int mime_types_size;
	struct http_mime_type_hash_entry **mime_types_hash;

	uint16_t log_flags;
	int log_fd;
	struct target_dataset *dset;

	struct target_conntrack_priv_http *ct_privs;

	struct perf_item *perf_tot_conn;
	struct perf_item *perf_cur_conn;
	struct perf_item *perf_dumped_files;
	struct perf_item *perf_dumped_bytes;
	struct perf_item *perf_open_files;
	struct perf_item *perf_parsed_reqs;
	struct perf_item *perf_parsed_resps;
	struct perf_item *perf_parse_errors;

};


int target_register_http(struct target_reg *r);

int target_init_http(struct target *t);
int target_open_http(struct target *t);
int target_process_http(struct target *t, struct frame *f);
int target_close_connection_http(struct target *t, struct conntrack_entry *ce, void *conntrack_priv);
int target_close_http(struct target *t);
int target_cleanup_http(struct target *t);

size_t target_parse_query_response_http(struct target_priv_http *priv, struct target_conntrack_priv_http *cp, char *pload, size_t psize);
int target_parse_response_headers_http(struct target_priv_http *priv, struct target_conntrack_priv_http *cp);
#ifdef HAVE_ZLIB
size_t target_process_gzip_http(struct target_priv_http *priv, struct target_conntrack_priv_http *cp, char * pload, size_t size);
#endif
int target_reset_conntrack_http(struct target_priv_http *priv, struct target_conntrack_priv_http *cp);
int target_buffer_payload_http(struct target_conntrack_priv_http *cp, char *pload, size_t psize);
int target_file_open_http(struct target *t, struct target_conntrack_priv_http *cp, struct frame *f, int is_gzip);


#endif
