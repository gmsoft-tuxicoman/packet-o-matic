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


#include "match_80211.h"
#include "ptype_mac.h"
#include "ptype_uint8.h"

#include <sys/socket.h>


static struct match_dep *match_undefined, *match_ipv4, *match_ipv6, *match_arp;

static int field_saddr, field_daddr, field_baddr, field_type, field_subtype;

static struct ptype *ptype_mac, *ptype_u8;

int match_register_80211(struct match_reg *r) {

	r->identify = match_identify_80211;
	r->unregister = match_unregister_80211;
	
	match_undefined = match_add_dependency(r->type, "undefined");
	match_ipv4 = match_add_dependency(r->type, "ipv4");
	match_ipv6 = match_add_dependency(r->type, "ipv6");
	match_arp = match_add_dependency(r->type, "arp");

	ptype_mac = ptype_alloc ("mac", NULL);

	if (!ptype_mac)
		return POM_ERR;

	ptype_u8 = ptype_alloc ("uint8", NULL);

	if (!ptype_u8)
		return POM_ERR;

	field_saddr = match_register_field(r->type, "src", ptype_mac, "Source MAC address");
	field_daddr = match_register_field(r->type, "dst", ptype_mac, "Destination MAC address");
	field_baddr = match_register_field(r->type, "bssid", ptype_mac, "BSSID MAC address");

	field_type = match_register_field(r->type, "type", ptype_u8, "802.11 frame type");
	field_subtype = match_register_field(r->type, "subtype", ptype_u8, "802.11 frame sub-type");

	return POM_OK;

}

static int match_identify_80211(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	if (sizeof(struct ieee80211_hdr) > len)
		return POM_ERR;

	struct ieee80211_hdr *i80211hdr = f->buff + start;

	int offt = 0;
	
	int ret = match_undefined->id;

	PTYPE_UINT8_SETVAL(l->fields[field_type], i80211hdr->u1.fc.type);
	PTYPE_UINT8_SETVAL(l->fields[field_subtype], i80211hdr->u1.fc.subtype);

	switch (i80211hdr->u1.fc.type) {
		case WLAN_FC_TYPE_MGMT:
			/* Management frames */
			switch (i80211hdr->u1.fc.subtype) {
				case WLAN_FC_SUBTYPE_PROBEREQ:
					PTYPE_MAC_SETADDR(l->fields[field_saddr], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(l->fields[field_baddr], i80211hdr->addr2);
					offt = 24;
					break;
				case WLAN_FC_SUBTYPE_DISASSOC:
				case WLAN_FC_SUBTYPE_AUTH:
				case WLAN_FC_SUBTYPE_DEAUTH:
					PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(l->fields[field_saddr], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(l->fields[field_baddr], i80211hdr->addr3);
					offt = 24;
					break;
				default:
					PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(l->fields[field_saddr], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(l->fields[field_baddr], i80211hdr->addr3);
					offt = 32;
					break;
			}
			break;
		case WLAN_FC_TYPE_CTRL:
			/* Error out on PHY */
			return POM_ERR;
			break;
		case WLAN_FC_TYPE_DATA:
			/* Data frames can have funny-length headers and offsets */

			/* Handle QoS */
			switch (i80211hdr->u1.fc.subtype) {
				case 8:
				case 9:
				case 10:
				case 11:
				case 12:
				case 14:
				case 15:
					offt += 2;
					break;
			}

			if (i80211hdr->u1.fc.to_ds == 0 && i80211hdr->u1.fc.from_ds == 0) {
				PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr1);
				PTYPE_MAC_SETADDR(l->fields[field_saddr], i80211hdr->addr2);
				PTYPE_MAC_SETADDR(l->fields[field_baddr], i80211hdr->addr3);
				offt += 24;
			} else if (i80211hdr->u1.fc.to_ds == 0 && 
					   i80211hdr->u1.fc.from_ds == 1) {
				PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr1);
				PTYPE_MAC_SETADDR(l->fields[field_baddr], i80211hdr->addr2);
				PTYPE_MAC_SETADDR(l->fields[field_saddr], i80211hdr->addr3);
				offt += 24;
			} else if (i80211hdr->u1.fc.to_ds == 1 && 
					   i80211hdr->u1.fc.from_ds == 0) {
				PTYPE_MAC_SETADDR(l->fields[field_baddr], i80211hdr->addr1);
				PTYPE_MAC_SETADDR(l->fields[field_saddr], i80211hdr->addr2);
				PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr3);
				offt += 24;
			} else if (i80211hdr->u1.fc.to_ds == 1 && 
					   i80211hdr->u1.fc.from_ds == 1) {
				if (len < offt + 30)
					return POM_ERR;

				PTYPE_MAC_SETADDR(l->fields[field_baddr], i80211hdr->addr2);
				PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr1);
				PTYPE_MAC_SETADDR(l->fields[field_saddr], f->buff + start + sizeof(i80211hdr));
				offt += 30;
			}

			if (start + offt + sizeof(struct ieee80211_llc) > len)
				return POM_ERR;

			struct ieee80211_llc *llc = f->buff + start + offt;

			if (llc->dsnap != 0xaa || llc->ssap != 0xaa ||
				llc->control != 0x03) {
				// looks like wrong LLC? 
				return POM_ERR;
			}

			offt += sizeof(struct ieee80211_llc);

			switch (ntohs(llc->ethertype)) {
				case 0x0800:
					ret = match_ipv4->id;
					break;
				case 0x0806:
					ret = match_arp->id;
					break;
				case 0x86dd:
					ret = match_ipv6->id;
					break;
			}

	}

	l->payload_start = start + offt;
	l->payload_size = len - offt;

	return ret;
}

static int match_unregister_80211(struct match_reg *r) {

	ptype_cleanup(ptype_mac);
	ptype_cleanup(ptype_u8);

	return POM_OK;
}
