/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
 *  Copyright (C) 2009 Mike Kershaw <dragorn@kismetwireless.net>
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


#include "match_ppi.h"

#include <ppi.h>

static struct match_dep *match_80211;

int match_register_ppi(struct match_reg *r) {

	r->identify = match_identify_ppi;
	
	match_80211 = match_add_dependency(r->type, "80211");

	return POM_OK;

}

static int match_identify_ppi(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	ppi_packet_header *ppihdr = f->buff + start;
	
	if (len > sizeof(ppi_packet_header) &&
		le16(ppihdr->pph_len) < len) {

		unsigned int header_len = le16(ppihdr->pph_len);
		l->payload_start = start + header_len;
		l->payload_size = len - header_len;
	} else {
		return POM_ERR;
	}

	return match_80211->id;
}
