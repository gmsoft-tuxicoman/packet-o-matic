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


#ifndef __MATCH_DOCSIS_H__
#define __MATCH_DOCSIS_H__


#include "modules_common.h"
#include "match.h"


struct docsis_hdr {

#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char ehdr_on:1;
	unsigned char fc_parm:5;
	unsigned char fc_type:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char fc_type:2;
	unsigned char fc_parm:5;
	unsigned char ehdr_on:1;
#else
# error "Please fix <bits/endian.h>"
#endif
	char mac_parm;
	uint16_t len;
	uint16_t hcs; // can also be start of ehdr. See SCTE 22-12002 section 6.2.1.4

};

struct docsis_ehdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int eh_len:4;
	unsigned int eh_type:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int eh_type:4;
	unsigned int eh_len:4;
#else
# error "Please fix <bits/endian.h>"
#endif

	char eh_value[15];

};

struct match_priv_docsis {
	unsigned char fc_type;
	unsigned char fc_type_mask;
};

// Definition of the standard types

#define FC_TYPE_PKT_MAC	0x0 // Packet-based MAC frame
#define FC_TYPE_ATM	0x1 // ATM cell MAC frame
#define FC_TYPE_RSVD	0x2 // Reserved PDU MAC frame
#define FC_TYPE_MAC_SPC 0x3 // MAC-specific header


// Definition of mac management mac_parm values
#define FCP_TIMING	0x00 // Timing header
#define FCP_MGMT	0x01 // Management header
#define FCP_REQ		0x02 // Request header (upstream only)
#define FCP_CONCAT	0x1C // Concatenation header (upstream only)


int match_register_docsis(struct match_reg *r, struct match_functions *m_funcs);
int match_init_docsis(struct match *m);
int match_identify_docsis(struct frame *f, struct layer* l, unsigned int start, unsigned int len);
int match_reconfig_docsis(struct match *m);
int match_eval_docsis(struct match* match, struct frame *f, unsigned int start, unsigned int len, struct layer *l);
int match_cleanup_docsis(struct match *m);

#endif
