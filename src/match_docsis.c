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

#include "match_docsis.h"
#include "ptype_uint8.h"

static struct match_dep *match_atm, *match_ethernet;

static int field_fc_type, field_fc_parm;

static struct ptype *ptype_uint8;

int match_register_docsis(struct match_reg *r) {

	r->identify = match_identify_docsis;
	r->unregister = match_unregister_docsis;

	match_atm = match_add_dependency(r->type, "atm");
	match_ethernet = match_add_dependency(r->type, "ethernet");

	ptype_uint8 = ptype_alloc("uint8", NULL);
	if (!ptype_uint8) 
		return POM_ERR;

	field_fc_type = match_register_field(r->type, "fc_type", ptype_uint8, "Frame control type");
	field_fc_parm = match_register_field(r->type, "fc_parm", ptype_uint8, "Frame parameters");

	return POM_OK;
}


static int match_identify_docsis(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct docsis_hdr *dhdr = f->buff + start;
	

	l->payload_start = start + sizeof(struct docsis_hdr);
	l->payload_size = ntohs(dhdr->len);

	if (dhdr->ehdr_on) {
		// fc_parm is len of ehdr if ehdr_on == 1
		l->payload_start += dhdr->fc_parm;
		l->payload_size -= dhdr->fc_parm;

		// TODO : process the ehdr
	}

	PTYPE_UINT8_SETVAL(l->fields[field_fc_type], dhdr->fc_type);
	PTYPE_UINT8_SETVAL(l->fields[field_fc_parm], dhdr->fc_parm);


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
	return POM_ERR;
}

static int match_unregister_docsis(struct match_reg *r) {

	ptype_cleanup(ptype_uint8);
	return POM_OK;

}
