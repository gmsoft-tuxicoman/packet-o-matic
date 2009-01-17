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


#ifndef __TARGET_HTTP_LOG_H__
#define	__TARGET_HTTP_LOG_H__

#include <target_http.h>


#define HTTP_LOG_ENABLED		0x0001
#define HTTP_LOG_CLIENT_IP		0x0002
#define HTTP_LOG_SERVER_IP		0x0004
#define HTTP_LOG_SERVER_PORT		0x0008
#define HTTP_LOG_TIME			0x0010
#define HTTP_LOG_REQUEST_PROTOCOL	0x0020
#define HTTP_LOG_REQUEST_METHOD		0x0040
#define HTTP_LOG_FIRST_LINE		0x0080
#define HTTP_LOG_REMOTE_USER		0x0100
#define HTTP_LOG_URL			0x0200
#define HTTP_LOG_SERVERNAME 		0x0400
#define HTTP_LOG_FILENAME		0x0800
#define HTTP_LOG_CREDENTIALS		0x1000
#define HTTP_LOG_LOGGED_QUERY		0x2000
#define HTTP_LOG_LOGGED_RESPONSE	0x4000


struct http_log_info {

	uint16_t log_flags;

	char *server_host, *server_port, *client_host;
	char *request_proto, *request_method;
	char *first_line;
	char *url;
	char *filename;
	struct timeval query_time, response_time;

};

int target_init_log_http(struct target_priv_http *priv);
int target_initial_log_http(struct target_conntrack_priv_http *cp, struct frame *f, struct layer *lastl);
int target_write_log_http(struct target_priv_http *priv, struct target_conntrack_priv_http *cp);

#endif
