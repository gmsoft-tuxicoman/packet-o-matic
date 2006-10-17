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


#ifndef __MATCH_TCP_H__
#define __MATCH_TCP_H__


#include "modules_common.h"
#include "match.h"


struct match_priv_tcp {

	unsigned short sport_min;
	unsigned short sport_max;
	unsigned short dport_min;
	unsigned short dport_max;

};


int match_register_tcp();
int match_init_tcp(struct match *m);
int match_reconfig_tcp(struct match *m);
int match_eval_tcp(struct match* match, void* frame, unsigned int start, unsigned int len);
int match_cleanup_tcp(struct match *m);

#endif
