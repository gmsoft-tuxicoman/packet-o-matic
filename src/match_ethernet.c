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


#include "match_ethernet.h"
#include "ptype_mac.h"

#include <net/ethernet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>

#ifdef HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif

int match_ipv4_id, match_ipv6_id, match_arp_id;
struct match_functions *mf;

struct match_field_reg *field_saddr, *field_daddr;

struct ptype *ptype_mac;

int match_register_ethernet(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_ethernet;
	r->unregister = match_unregister_ethernet;
	
	mf = m_funcs;
	
	match_ipv4_id = (*mf->match_register) ("ipv4");
	match_ipv6_id = (*mf->match_register) ("ipv6");
	match_arp_id = (*mf->match_register) ("arp");

	ptype_mac = (*mf->ptype_alloc) ("mac", NULL);

	if (!ptype_mac)
		return POM_ERR;

	field_saddr = (*mf->register_field) (r->type, "src", ptype_mac, "Source MAC address");
	field_daddr = (*mf->register_field) (r->type, "dst", ptype_mac, "Destination MAC address");

	return POM_OK;

}

int match_identify_ethernet(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct ether_header *ehdr = f->buff + start;

	l->payload_start = start + sizeof(struct ether_header);
	l->payload_size = len - sizeof(struct ether_header);


	struct layer_field *lf = l->fields;
	while (lf) {
		if (lf->type == field_saddr) {
			PTYPE_MAC_SETADDR(lf->value, ehdr->ether_shost);
		} else if (lf->type == field_daddr) {
			PTYPE_MAC_SETADDR(lf->value, ehdr->ether_dhost);
		}
		lf = lf->next;
	}

	switch (ntohs(ehdr->ether_type)) {
		case 0x0800:
			return  match_ipv4_id;
		case 0x0806:
			return match_arp_id;
		case 0x86dd:
			return match_ipv6_id;
	}

	return POM_ERR;
}

int match_unregister_ethernet(struct match_reg *r) {

	(*mf->ptype_cleanup) (ptype_mac);

	return POM_OK;
}
