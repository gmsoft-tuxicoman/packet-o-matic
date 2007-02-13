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

#include "match_linux_cooked.h"

#include <sys/socket.h>

int match_ipv4_id, match_ipv6_id;
struct match_functions *m_functions;

int match_register_linux_cooked(struct match_reg *r, struct match_functions *m_funcs) {

	r->init = match_init_linux_cooked;
	r->identify = match_identify_linux_cooked;
	r->cleanup = match_cleanup_linux_cooked;

	m_functions = m_funcs;
	
	return 1;
}

int match_init_linux_cooked(struct match *m) {

	match_ipv4_id = (*m_functions->match_register) ("ipv4");
	match_ipv6_id = (*m_functions->match_register) ("ipv6");
	return 1;

}

int match_identify_linux_cooked(struct layer* l, void* frame, unsigned int start, unsigned int len) {

	struct cooked_hdr *chdr = frame + start;

	l->payload_start = start + sizeof(struct cooked_hdr);
	l->payload_size = len - sizeof(struct cooked_hdr);

	ndprint("Processing linux cooked frame -> PKT TYPE : 0x%04x ", (unsigned) chdr->pkt_type);
	ndprint("| DEV TYPE : 0x%04x ",  chdr->dev_type);
	ndprint("| SADDR : 0x%04x ", chdr->ll_saddr);
	ndprint("| ETHER TYPE : 0x%04x ", chdr->ether_type);

	switch (ntohs(chdr->ether_type)) {
		case 0x0800:
			ndprint("| IPv4 packet\n");
			return  match_ipv4_id;
			break;
		case 0x86dd:
			ndprint("| IPv6 packet\n");
			return match_ipv6_id;
			break;
		default:
			ndprint("| Unhandled packet\n");
	}

	return -1;
}

int match_cleanup_linux_cooked(struct match *m) {

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
