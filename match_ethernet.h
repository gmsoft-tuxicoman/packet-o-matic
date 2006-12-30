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


#ifndef __MATCH_ETHERNET_H__
#define __MATCH_ETHERNET_H__


#include "modules_common.h"
#include "match.h"

#include <linux/if_ether.h>


struct match_priv_ethernet {

	unsigned char smac[6];
	unsigned char smac_mask[6];
	unsigned char dmac[6];
	unsigned char dmac_mask[6];
	unsigned char proto[2];
	unsigned char proto_mask[2];
	
};

int match_register_ethernet(struct match_reg *r);
int match_init_ethernet(struct match *m);
int match_reconfig_ethernet(struct match *m);
int match_identify_ethernet(struct layer* match, void* frame, unsigned int start, unsigned int len);
int match_eval_ethernet(struct match* match, void* frame, unsigned int start, unsigned int len, struct layer *l);
int match_cleanup_ethernet(struct match *m);


#endif
