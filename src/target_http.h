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

#define HTTP_HEADER	0x01 ///< Looking for a header
#define HTTP_NO_MATCH	0x02 ///< We got all the info but we don't care about that payload
#define HTTP_MATCH	0x04 ///< We got all the info and it match what we care about
#define HTTP_HAVE_CTYPE	0x10 ///< We have the content type
#define HTTP_HAVE_CLEN	0x20 ///< We have the content length

struct target_conntrack_priv_http {

	int fd;
	unsigned int state;
	unsigned int direction;
	unsigned int pos;
	unsigned int content_len;
	unsigned int content_type; // index in the mime_type array

	struct conntrack_entry *ce;
	struct target_conntrack_priv_http *next;
	struct target_conntrack_priv_http *prev;
};


struct target_priv_http {

	int match_mask;

	struct ptype *path;
	struct ptype *dump_img;
	struct ptype *dump_vid;
	struct ptype *dump_snd;
	struct ptype *dump_txt;
	struct ptype *dump_bin;
	struct ptype *dump_doc;

	struct target_conntrack_priv_http *ct_privs;

};


int target_register_http(struct target_reg *r);

int target_init_http(struct target *t);
int target_open_http(struct target *t);
int target_process_http(struct target *t, struct frame *f);
int target_close_connection_http(struct target *t, struct conntrack_entry *ce, void *conntrack_priv);
int target_close_http(struct target *t);
int target_cleanup_http(struct target *t);

#endif
