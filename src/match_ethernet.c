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


#include "match_ethernet.h"
#include "ptype_mac.h"

#include <sys/socket.h>


struct match_dep *match_ipv4, *match_ipv6, *match_arp, *match_vlan;

int field_saddr, field_daddr;

struct ptype *ptype_mac;

int match_register_ethernet(struct match_reg *r) {

	r->identify = match_identify_ethernet;
	r->unregister = match_unregister_ethernet;
	
	match_ipv4 = match_add_dependency(r->type, "ipv4");
	match_ipv6 = match_add_dependency(r->type, "ipv6");
	match_arp = match_add_dependency(r->type, "arp");
	match_vlan = match_add_dependency(r->type, "vlan");

	ptype_mac = ptype_alloc ("mac", NULL);

	if (!ptype_mac)
		return POM_ERR;

	field_saddr = match_register_field(r->type, "src", ptype_mac, "Source MAC address");
	field_daddr = match_register_field(r->type, "dst", ptype_mac, "Destination MAC address");

	return POM_OK;

}

int match_identify_ethernet(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct ether_header *ehdr = f->buff + start;

	l->payload_start = start + sizeof(struct ether_header);
	l->payload_size = len - sizeof(struct ether_header);


	PTYPE_MAC_SETADDR(l->fields[field_saddr], ehdr->ether_shost);
	PTYPE_MAC_SETADDR(l->fields[field_daddr], ehdr->ether_dhost);

	switch (ntohs(ehdr->ether_type)) {
		case 0x0800:
			return match_ipv4->id;
		case 0x0806:
			return match_arp->id;
		case 0x8100:
			return match_vlan->id;
		case 0x86dd:
			return match_ipv6->id;
	}

	return POM_ERR;
}

int match_unregister_ethernet(struct match_reg *r) {

	ptype_cleanup(ptype_mac);

	return POM_OK;
}
