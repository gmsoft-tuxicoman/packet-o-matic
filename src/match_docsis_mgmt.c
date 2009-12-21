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

#include <stddef.h>

#include "match_docsis_mgmt.h"
#include "ptype_uint8.h"
#include "ptype_mac.h"

static struct match_dep *match_undefined;

static int field_saddr, field_daddr, field_dsap, field_ssap, field_control, field_version, field_type;

static struct ptype *ptype_uint8, *ptype_mac;

int match_register_docsis_mgmt(struct match_reg *r) {

	r->identify = match_identify_docsis_mgmt;
	r->unregister = match_unregister_docsis_mgmt;

	match_undefined = match_add_dependency(r->type, "undefined");

	ptype_uint8 = ptype_alloc("uint8", NULL);
	ptype_mac = ptype_alloc("mac", NULL);
	if (!ptype_uint8 || ! ptype_mac) 
		return POM_ERR;

	field_saddr = match_register_field(r->type, "saddr", ptype_mac, "Source address");
	field_daddr = match_register_field(r->type, "daddr", ptype_mac, "Destination address");
	field_dsap = match_register_field(r->type, "dsap", ptype_uint8, "DSAP");
	field_ssap = match_register_field(r->type, "ssap", ptype_uint8, "SSAP");
	field_control = match_register_field(r->type, "control", ptype_uint8, "Control");
	field_version = match_register_field(r->type, "version", ptype_uint8, "Version");
	field_type = match_register_field(r->type, "type", ptype_uint8, "Type");

	return POM_OK;
}


static int match_identify_docsis_mgmt(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct docsis_mgmt_hdr *dmhdr = f->buff + start;
	
	if ((len < sizeof(struct docsis_mgmt_hdr) + (sizeof(uint16_t))) ||
		(ntohs(dmhdr->len) + offsetof(struct docsis_mgmt_hdr, dsap) + (sizeof(uint16_t)) > len))
		return POM_ERR;

	l->payload_start = start + sizeof(struct docsis_mgmt_hdr);
	l->payload_size = ntohs(dmhdr->len) - (sizeof(struct docsis_mgmt_hdr) - offsetof(struct docsis_mgmt_hdr, dsap));

	PTYPE_MAC_SETADDR(l->fields[field_saddr], dmhdr->saddr);
	PTYPE_MAC_SETADDR(l->fields[field_daddr], dmhdr->daddr);
	PTYPE_UINT8_SETVAL(l->fields[field_dsap], dmhdr->dsap);
	PTYPE_UINT8_SETVAL(l->fields[field_ssap], dmhdr->ssap);
	PTYPE_UINT8_SETVAL(l->fields[field_control], dmhdr->control);
	PTYPE_UINT8_SETVAL(l->fields[field_version], dmhdr->version);
	PTYPE_UINT8_SETVAL(l->fields[field_type], dmhdr->type);

	return match_undefined->id;
}

static int match_unregister_docsis_mgmt(struct match_reg *r) {

	ptype_cleanup(ptype_uint8);
	ptype_cleanup(ptype_mac);
	return POM_OK;

}
