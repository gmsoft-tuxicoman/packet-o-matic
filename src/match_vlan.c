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


#include "match_vlan.h"
#include "ptype_uint16.h"

static struct match_dep *match_ipv4, *match_ipv6, *match_arp, *match_vlan;

static int field_vid;

static struct ptype *ptype_vid;

int match_register_vlan(struct match_reg *r) {

	r->identify = match_identify_vlan;
	r->get_expectation = match_get_expectation_vlan;
	r->unregister = match_unregister_vlan;
	
	match_ipv4 = match_add_dependency(r->type, "ipv4");
	match_ipv6 = match_add_dependency(r->type, "ipv6");
	match_arp = match_add_dependency(r->type, "arp");
	match_vlan = match_add_dependency(r->type, "vlan");

	ptype_vid = ptype_alloc("uint16", NULL);

	if (!ptype_vid)
		return POM_ERR;

	field_vid = match_register_field(r->type, "vid", ptype_vid, "Vlan ID");

	return POM_OK;

}

static int match_identify_vlan(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct vlan_header *vhdr = f->buff + start;

	if (len < sizeof(struct vlan_header))
		return POM_ERR;

	l->payload_start = start + sizeof(struct vlan_header);
	l->payload_size = len - sizeof(struct vlan_header);


	PTYPE_UINT16_SETVAL(l->fields[field_vid], ntohs(vhdr->vid));

	switch (ntohs(vhdr->ether_type)) {
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

static int match_get_expectation_vlan(int field_id, int direction) {

	if (field_id == field_vid)
		return field_vid;

	return POM_ERR;
}

static int match_unregister_vlan(struct match_reg *r) {

	ptype_cleanup(ptype_vid);

	return POM_OK;
}
