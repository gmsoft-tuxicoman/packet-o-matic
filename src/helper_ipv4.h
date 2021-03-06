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


#ifndef __HELPER_IPV4_H__
#define __HELPER_IPV4_H__


#include "modules_common.h"
#include "helper.h"

struct helper_priv_ipv4_frag {

	char *buffer;
	u_short offset;
	size_t len;
	int last; // 1 if this is the last fragment in the packet

	struct helper_priv_ipv4_frag *next;
	struct helper_priv_ipv4_frag *prev;
};


struct helper_priv_ipv4 {

	struct frame *f; ///< hold info about the original packet
	unsigned int hdr_offset; ///< ipv4 header offset in the buffer contained in the frame structure
	struct timer *t;

	struct helper_priv_ipv4_frag * frags;
	struct helper_priv_ipv4 *next;
	struct helper_priv_ipv4 *prev;

};


int helper_register_ipv4(struct helper_reg *r);
static int helper_need_help_ipv4(struct frame *f, unsigned int start, unsigned int len, struct layer *l);
static int helper_resize_ipv4(struct frame *f, unsigned int start, unsigned int new_psize);
static int helper_cleanup_ipv4_frag(void *priv);
static int helper_cleanup_ipv4();


#endif

