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

#include "match_docsis.h"
#include "ptype_uint8.h"

int match_atm_id, match_ethernet_id;
struct match_functions *m_functions;
struct layer_info *match_fc_type_info, *match_ehdr_on_info, *match_fc_parm_info;

struct ptype *field_fc_type;

int match_register_docsis(struct match_reg *r, struct match_functions *m_funcs) {

	r->identify = match_identify_docsis;
	r->unregister = match_unregister_docsis;

	m_functions = m_funcs;
	
	match_atm_id = (*m_functions->match_register) ("atm");
	match_ethernet_id = (*m_functions->match_register) ("ethernet");

	match_fc_type_info = (*m_funcs->layer_info_register) (r->type, "fc_type", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_ZERO);
	match_fc_parm_info = (*m_funcs->layer_info_register) (r->type, "fc_parm", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_ZERO);
	match_ehdr_on_info = (*m_funcs->layer_info_register) (r->type, "ehdr_on", LAYER_INFO_TYPE_UINT32);

	field_fc_type = (*m_funcs->ptype_alloc) ("uint8", NULL);
	if (!field_fc_type)
		return POM_ERR;

	(*m_funcs->register_param) (r->type, "fc_type", field_fc_type, "Frame control type");

	return POM_OK;
}


int match_identify_docsis(struct frame *f, struct layer* l, unsigned int start, unsigned int len) {

	struct docsis_hdr *dhdr = f->buff + start;
	

	l->payload_start = start + sizeof(struct docsis_hdr);

	match_fc_type_info->val.ui32 = dhdr->fc_type;
	match_fc_parm_info->val.ui32 = dhdr->fc_parm;
	match_ehdr_on_info->val.ui32 = dhdr->ehdr_on;

	l->payload_size = ntohs(dhdr->len);

	if (dhdr->ehdr_on) {
		// fc_parm is len of ehdr if ehdr_on == 1
		l->payload_start += dhdr->fc_parm;
		l->payload_size -= dhdr->fc_parm;

		// TODO : process the ehdr
	}

	PTYPE_UINT8_SETVAL(field_fc_type, dhdr->fc_type);

	switch (dhdr->fc_type) {
		case FC_TYPE_PKT_MAC:
			// We don't need the 4 bytes of ethernet checksum
			l->payload_size -= 4;
			return match_ethernet_id;
		case FC_TYPE_ATM:
			return match_atm_id;
		case FC_TYPE_RSVD:
			return -1;
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
	return -1;
}

int match_unregister_docsis(struct match_reg *r) {

	(*m_functions->ptype_cleanup) (field_fc_type);
	return POM_OK;
}
