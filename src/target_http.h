/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
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

#define HTTP_HEADER	0x01
#define HTTP_NO_MATCH	0x02
#define HTTP_MATCH	0x04
#define HTTP_HAVE_CTYPE	0x10
#define HTTP_HAVE_CLEN	0x20

struct target_conntrack_priv_http {

	int fd;
	unsigned int state;
	unsigned int direction;
	unsigned int pos;
	unsigned int content_len;
	unsigned int content_type; // index in the mime_type array

};



int target_register_http(struct target_reg *r, struct target_functions *tg_funcs);

int target_init_http(struct target *t);
int target_process_http(struct target *t, struct frame *f);
int target_close_connection_http(struct conntrack_entry *ce, void *conntrack_priv);
int target_cleanup_http(struct target *t);

#endif
