/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2009 Guy Martin <gmsoft@tuxicoman.be>
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

#include "helper_docsis.h"


int helper_register_docsis(struct helper_reg *r) {
	
	r->resize = helper_resize_docsis;
	return POM_OK;
}

static int helper_resize_docsis(struct frame *f, unsigned int start, unsigned int new_psize) {


	struct docsis_hdr *dhdr = f->buff + start;

	if (dhdr->fc_type == FC_TYPE_PKT_MAC || dhdr->fc_type == FC_TYPE_ISOLATION_PKT_MAC)
		new_psize += 4; // Add ethernet checksum size

	if (dhdr->ehdr_on)
		dhdr->len = htons(new_psize + dhdr->mac_parm);
	else
		dhdr->len = htons(new_psize);

	return POM_OK;
}

