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

#define PARAMS_NUM 1

char *match_docsis_params[PARAMS_NUM][3] = {
	{ "fc_type", "0/0", "FC_TYPE to match. default : 0/0" },
};



int match_atm_id, match_ethernet_id;
struct match_functions *m_functions;
struct layer_info *match_fc_type_info, *match_ehdr_on_info, *match_fc_parm_info;

int match_register_docsis(struct match_reg *r, struct match_functions *m_funcs) {

	copy_params(r->params_name, match_docsis_params, 0, PARAMS_NUM);
	copy_params(r->params_help, match_docsis_params, 2, PARAMS_NUM);

	r->identify = match_identify_docsis;
	r->init = match_init_docsis;
	r->eval = match_eval_docsis;
	r->reconfig = match_reconfig_docsis;
	r->cleanup = match_cleanup_docsis;

	m_functions = m_funcs;
	
	match_atm_id = (*m_functions->match_register) ("atm");
	match_ethernet_id = (*m_functions->match_register) ("ethernet");

	match_fc_type_info = (*m_funcs->layer_info_register) (r->type, "fc_type", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_ZERO);
	match_fc_parm_info = (*m_funcs->layer_info_register) (r->type, "fc_parm", LAYER_INFO_TYPE_UINT32 | LAYER_INFO_PRINT_ZERO);
	match_ehdr_on_info = (*m_funcs->layer_info_register) (r->type, "ehdr_on", LAYER_INFO_TYPE_UINT32);


	return 1;
}

int match_init_docsis(struct match *m) {

	copy_params(m->params_value, match_docsis_params, 1, PARAMS_NUM);
	return 1;
}

int match_reconfig_docsis(struct match *m) {

	if (!m->match_priv) {
		m->match_priv = malloc(sizeof(struct match_priv_docsis));
		bzero(m->match_priv, sizeof(struct match_priv_docsis));
	}

	struct match_priv_docsis *p = m->match_priv;

	if (sscanf(m->params_value[0], "%hhu/%hhu", &p->fc_type, &p->fc_type_mask) != 2) {
		if (sscanf(m->params_value[0], "%hhu", &p->fc_type)) {
			p->fc_type_mask = 0xff;
		} else
			return 0;
	}
	p->fc_type &= 0x3;
	p->fc_type_mask &= 0x3;
				
	return 1;
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

	switch (dhdr->fc_type) {
		case FC_TYPE_PKT_MAC:
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

int match_eval_docsis(struct match* match, struct frame *f, unsigned int start, unsigned int len, struct layer *l) {

	
	struct docsis_hdr *dhdr = f->buff + start;

	struct match_priv_docsis *p =  match->match_priv;

	return !((dhdr->fc_type & p->fc_type_mask) == (p->fc_type & p->fc_type_mask));
}

int match_cleanup_docsis(struct match *m) {

	clean_params(m->params_value, PARAMS_NUM);

	if (m->match_priv)
		free(m->match_priv);


	return 1;
}
