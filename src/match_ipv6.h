/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __MATCH_IPV6_H__
#define __MATCH_IPV6_H__


#include "modules_common.h"
#include "match.h"
#include <netinet/in.h>
#include <netinet/ip6.h>


struct match_priv_ipv6 {

	struct in6_addr saddr;
	unsigned char snetmask[16];
	struct in6_addr daddr;
	unsigned char dnetmask[16];
	unsigned int flabel;
	unsigned int flabelmask;
};


int match_register_ipv6(struct match_reg *r, struct match_functions *m_funcs);
int match_init_ipv6(struct match *m);
int match_reconfig_ipv6(struct match *m);
int match_identify_ipv6(struct layer* l, void* frame, unsigned int start, unsigned int len);
int match_eval_ipv6(struct match* match, void* frame, unsigned int start, unsigned int len, struct layer *l);
int match_cleanup_ipv6(struct match *m);


#endif
