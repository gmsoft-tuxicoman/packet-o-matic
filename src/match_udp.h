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


#ifndef __MATCH_UDP_H__
#define __MATCH_UDP_H__


#include "modules_common.h"
#include "match.h"

struct match_priv_udp {

	unsigned short sport_min;
	unsigned short sport_max;
	unsigned short dport_min;
	unsigned short dport_max;

};


int match_register_udp();

int match_register_udp();
int match_init_udp(struct match *m);
int match_reconfig_udp(struct match *m);
int match_identify_udp(struct frame *f, struct layer* l, unsigned int start, unsigned int len);
int match_eval_udp(struct match* match, struct frame *f, unsigned int start, unsigned int len, struct layer *l);
int match_cleanup_udp(struct match *m);


#endif
