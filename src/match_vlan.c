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


#include "match_vlan.h"
#include "ptype_uint16.h"

int match_ipv4_id, match_ipv6_id, match_arp_id, match_vlan_id;
struct match_functions *mf;

int field_vid;

struct ptype *ptype_vid;

int match_register_vlan(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_vlan;
	r->unregister = match_unregister_vlan;
	
	mf = m_funcs;
	
	match_ipv4_id = (*mf->match_register) ("ipv4");
	match_ipv6_id = (*mf->match_register) ("ipv6");
	match_arp_id = (*mf->match_register) ("arp");
	match_vlan_id = (*mf->match_register) ("vlan");

	ptype_vid = (*mf->ptype_alloc) ("uint16", NULL);

	if (!ptype_vid)
		return POM_ERR;

	field_vid = (*mf->register_field) (r->type, "vid", ptype_vid, "Vlan ID");

	return POM_OK;

}

int match_identify_vlan(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct vlan_header *vhdr = f->buff + start;

	l->payload_start = start + sizeof(struct vlan_header);
	l->payload_size = len - sizeof(struct vlan_header);


	PTYPE_UINT16_SETVAL(l->fields[field_vid], ntohs(vhdr->vid));

	switch (ntohs(vhdr->ether_type)) {
		case 0x0800:
			return match_ipv4_id;
		case 0x0806:
			return match_arp_id;
		case 0x8100:
			return match_vlan_id;
		case 0x86dd:
			return match_ipv6_id;
	}

	return POM_ERR;
}

int match_unregister_vlan(struct match_reg *r) {

	(*mf->ptype_cleanup) (ptype_vid);

	return POM_OK;
}
