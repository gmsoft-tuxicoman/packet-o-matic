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


#ifndef __MATCH_RTP_H__
#define __MATCH_RTP_H__

#include "modules_common.h"
#include "match.h"

struct rtphdr {
	
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char csrc_count:4;
	unsigned char extension:1;
	unsigned char padding:1;
	unsigned char version:2;

	unsigned char payload_type:7;
	unsigned char marker:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char version:2;
	unsigned char padding:1;
	unsigned char extension:1;
	unsigned char csrc_count:4;

	unsigned char marker:1;
	unsigned char payload_type:7;
#else
# error "Please fix <endian.h>"
#endif
	uint16_t seq_num;
	uint32_t timestamp;
	uint32_t ssrc;

};

struct rtphdrext {
	uint16_t profile_defined;
	uint16_t length;
	char *header_extension;
};



int match_register_rtp(struct match_reg *r);
int match_identify_rtp(struct frame *f, struct layer* l, unsigned int start, unsigned int len);
int match_get_expectation_rtp(int field_id, int direction);
int match_unregister_rtp(struct match_reg *r);


#endif
