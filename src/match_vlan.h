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


#ifndef __MATCH_VLAN_H__
#define __MATCH_VLAN_H__


#include "modules_common.h"
#include "match.h"

struct vlan_header {

#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t vid:12;
	uint16_t cfi:1;
	uint16_t user_priority:3;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t user_priority:3;
	uint16_t cfi:1;
	uint16_t vid:12;
#else
# error "Please fix <endian.h>"
#endif

	uint16_t ether_type;
};

int match_register_vlan(struct match_reg *r);
int match_identify_vlan(struct frame *f, struct layer* l, unsigned int start, unsigned int len);
int match_get_expectation_vlan(int field_id, int direction);
int match_unregister_vlan(struct match_reg *r);


#endif
