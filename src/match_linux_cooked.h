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


#ifndef __MATCH_LINUX_COOKED_H__
#define __MATCH_LINUX_COOKED_H__


#include "modules_common.h"
#include "match.h"


struct cooked_hdr {
	uint16_t pkt_type;
	uint16_t dev_type;
	uint16_t ll_saddr;
	char ll_hdr[8];
	uint16_t ether_type;

};

int match_register_linux_cooked(struct match_reg *r, struct match_functions *m_funcs);
int match_identify_linux_cooked(struct layer* l, void* frame, unsigned int start, unsigned int len);

#endif
