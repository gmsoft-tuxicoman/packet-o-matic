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


#ifndef __CONNTRACK_IPV4_H__
#define __CONNTRACK_IPV4_H__


#include "modules_common.h"
#include "conntrack.h"

struct conntrack_priv_ipv4 {

	uint32_t saddr;
	uint32_t daddr;

};

int conntrack_register_ipv4(struct conntrack_reg *r, struct conntrack_functions *ct_funcs);
uint32_t conntrack_get_hash_ipv4(void *frame, unsigned int start, unsigned int flags);
int conntrack_doublecheck_ipv4(void *frame, unsigned int start, void *priv, unsigned int flags);
void *conntrack_alloc_match_priv_ipv4(void *frame, unsigned int start, struct conntrack_entry *ce);
int conntrack_cleanup_match_priv_ipv4(void *priv);


#endif
