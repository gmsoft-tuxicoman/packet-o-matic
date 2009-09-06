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


#ifndef __PPPOE_H__
#define __PPPOE_H__

#include "config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

struct pppoe_hdr {

#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char ver:4;
	unsigned char type:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char type:4;
	unsigned char ver:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	unsigned char code;
	uint16_t sess_id;
	uint16_t len;
};

// Definition of PPPOE codes

#define PPPOE_CODE_DATA	0x00
#define PPPOE_CODE_PADI	0x09
#define PPPOE_CODE_PADO	0x07
#define PPPOE_CODE_PADR 0x19
#define PPPOE_CODE_PADS 0x65
#define PPPOE_CODE_PADT	0xA7

#endif
