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


#include "match_prism.h"

#include <prism.h>

static struct match_dep *match_80211;

int match_register_prism(struct match_reg *r) {

	r->identify = match_identify_prism;
	
	match_80211 = match_add_dependency(r->type, "80211");

	return POM_OK;

}

static int match_identify_prism(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	avs_80211_1_header *avshdr = f->buff + start;

	int header_len = 0;
	if (len > sizeof(avs_80211_1_header)
		&& ntohl(avshdr->version) == 0x80211001
		&& ntohl(avshdr->length) < len) {
		header_len = ntohl(avshdr->length);
	} else if (len > sizeof(wlan_ng_prism2_header)) {
		header_len = sizeof(wlan_ng_prism2_header);
	} else {
		// Invalid packet
		return POM_ERR;
	}

	l->payload_start = start + header_len;
	l->payload_size = len - header_len;


	return match_80211->id;
}
