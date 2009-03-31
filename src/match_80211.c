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

	if (len < 12) // Min length is 12 (CTRL ACK frame)
		return POM_ERR;

	struct ieee80211_hdr *i80211hdr = f->buff + start;

	int offt = 0;
	
	int ret = match_undefined->id;

	PTYPE_UINT8_SETVAL(l->fields[field_type], i80211hdr->u1.fc.type);
	PTYPE_UINT8_SETVAL(l->fields[field_subtype], i80211hdr->u1.fc.subtype);

	uint8_t empty_addr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	switch (i80211hdr->u1.fc.type) {
		case WLAN_FC_TYPE_MGMT:
			/* Management frames */
			if (len < 24)
				return POM_ERR;
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
			/* Control frame */
			switch (i80211hdr->u1.fc.subtype) {
				case WLAN_FC_SUBTYPE_PSPOLL:
				case WLAN_FC_SUBTYPE_RTS:
				case WLAN_FC_SUBTYPE_CFEND:
				case WLAN_FC_SUBTYPE_CFENDACK:
					PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(l->fields[field_saddr], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(l->fields[field_baddr], empty_addr);
					offt = 16;
					break;

				case WLAN_FC_SUBTYPE_CTS:
				case WLAN_FC_SUBTYPE_ACK:
					PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(l->fields[field_saddr], empty_addr);
					PTYPE_MAC_SETADDR(l->fields[field_baddr], empty_addr);
					offt = 10;
					break;

				case WLAN_FC_SUBTYPE_BLOCKACKREQ:
					PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(l->fields[field_saddr], i80211hdr->addr2);
					offt = 20; // 16 + 2 for BAR Control + 2 BAR Seq Control
					break;
				
				case WLAN_FC_SUBTYPE_BLOCKACK:
					PTYPE_MAC_SETADDR(l->fields[field_daddr], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(l->fields[field_saddr], i80211hdr->addr2);
					offt = 148; // 16 + 2 for BA Control + 2 Seq Control + 128 BA Bitmap
					break;

			}
			break;
		case WLAN_FC_TYPE_DATA:
			/* Data frames can have funny-length headers and offsets */

			if (len < 24)
				return POM_ERR;

			/* Handle QoS */
			switch (i80211hdr->u1.fc.subtype) {
				case WLAN_FC_SUBTYPE_QOSDATA:
				case WLAN_FC_SUBTYPE_QOSDATACFACK:
				case WLAN_FC_SUBTYPE_QOSDATACFPOLL:
				case WLAN_FC_SUBTYPE_QOSDATACFACKPOLL:
				case WLAN_FC_SUBTYPE_QOSNULL:
				case WLAN_FC_SUBTYPE_QOSNULLCFPOLL:
				case WLAN_FC_SUBTYPE_QOSNULLCFACKPOLL:
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

			if (i80211hdr->u1.fc.subtype & WLAN_FC_SUBTYPE_MASK_NODATA) {
				l->payload_start = start + offt;
				l->payload_size = 0;
				return ret;
			}

			if (offt + sizeof(struct ieee80211_llc) > len)
				return POM_ERR;

			struct ieee80211_llc *llc = f->buff + start + offt;

			if (llc->dsnap != 0xaa || llc->ssap != 0xaa ||
				llc->control != 0x03) {
				// looks like wrong LLC? 
				return match_undefined->id;
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

			break;

		default:
			return POM_ERR;

	}

	if (offt > len)
		return POM_ERR;

	l->payload_start = start + offt;
	l->payload_size = len - offt;

// x86 can do non aligned access 
#if !defined(__i386__) && !defined(__x86_64__)

	// Let's align the buffer
	// Why is this stupid header not always a multiple of 4 bytes ?
	char offset = (long)(f->buff + l->payload_start) & 3;
	if (offset) {
		if (f->buff - offset > f->buff_base) {
			memmove(f->buff - offset, f->buff, f->len);
			f->buff -= offset;
		} else {
			memmove(f->buff + offset, f->buff, f->len);
			f->buff += offset;

		}
	}

#endif

	return ret;
}

static int match_unregister_80211(struct match_reg *r) {

	ptype_cleanup(ptype_mac);
	ptype_cleanup(ptype_u8);

	return POM_OK;
}
