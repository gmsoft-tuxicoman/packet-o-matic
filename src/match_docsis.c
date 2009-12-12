/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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

#include "match_docsis.h"
#include "ptype_uint8.h"
#include "ptype_bool.h"

static struct match_dep *match_undefined, *match_atm, *match_ethernet;

static int field_fc_type, field_fc_parm, field_ehdr_on;

static struct ptype *ptype_uint8, *ptype_bool;

int match_register_docsis(struct match_reg *r) {

	r->identify = match_identify_docsis;
	r->unregister = match_unregister_docsis;

	match_undefined = match_add_dependency(r->type, "undefined");
	match_atm = match_add_dependency(r->type, "atm");
	match_ethernet = match_add_dependency(r->type, "ethernet");

	ptype_uint8 = ptype_alloc("uint8", NULL);
	ptype_bool = ptype_alloc("bool", NULL);
	if (!ptype_uint8 || ! ptype_bool) 
		return POM_ERR;

	field_fc_type = match_register_field(r->type, "fc_type", ptype_uint8, "Frame control type");
	field_fc_parm = match_register_field(r->type, "fc_parm", ptype_uint8, "Frame parameters");
	field_ehdr_on = match_register_field(r->type, "ehdr_on", ptype_bool, "Extended header");

	return POM_OK;
}


static int match_identify_docsis(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct docsis_hdr *dhdr = f->buff + start;
	
	if (len < sizeof(struct docsis_hdr) || ntohs(dhdr->len) > len)
		return POM_ERR;

	l->payload_start = start + sizeof(struct docsis_hdr);
	l->payload_size = ntohs(dhdr->len);

	PTYPE_UINT8_SETVAL(l->fields[field_fc_type], dhdr->fc_type);
	PTYPE_UINT8_SETVAL(l->fields[field_fc_parm], dhdr->fc_parm);
	PTYPE_BOOL_SETVAL(l->fields[field_ehdr_on], dhdr->ehdr_on);

	if (dhdr->ehdr_on) {

		if (dhdr->mac_parm > ntohs(dhdr->len))
			return POM_ERR;

		l->payload_start += dhdr->mac_parm;
		l->payload_size -= dhdr->mac_parm;
		
		// Make sure this is not matched as valid traffic
		struct docsis_ehdr *ehdr = (struct docsis_ehdr*) (dhdr + offsetof(struct docsis_hdr, hcs));
		if (ehdr->eh_type == EH_TYPE_BP_DOWN || ehdr->eh_type == EH_TYPE_BP_DOWN) 
			return match_undefined->id;
	}

	switch (dhdr->fc_type) {
		case FC_TYPE_PKT_MAC:
			// We don't need the 4 bytes of ethernet checksum
			l->payload_size -= 4;
			return match_ethernet->id;
		case FC_TYPE_ATM:
			return match_atm->id;
		case FC_TYPE_RSVD:
			return POM_ERR;
	}

	// At this point, only fc_type == FC_TYPE_MAC_SPC is left
/*
	switch (dhdr->fc_parm) {

		case FCP_TIMING:
		case FCP_MGMT:

		// XXX : not handled, upstream only
		case FCP_REQ:
		case FCP_CONCAT:
			return -1;
	}
*/
	return match_undefined->id;
}

static int match_unregister_docsis(struct match_reg *r) {

	ptype_cleanup(ptype_uint8);
	ptype_cleanup(ptype_bool);
	return POM_OK;

}
