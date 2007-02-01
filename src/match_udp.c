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

#include "match_udp.h"
#include <netinet/udp.h>


#define PARAMS_NUM 2

char *match_udp_params[PARAMS_NUM][3] = {

	{ "sport", "1:65535", "source port or port range"},
	{ "dport", "1:65535", "destination port or port range"},

};

int match_undefined_id;

int match_register_udp(struct match_reg *r) {


	copy_params(r->params_name, match_udp_params, 0, PARAMS_NUM);
	copy_params(r->params_help, match_udp_params, 2, PARAMS_NUM);

	r->init = match_init_udp;
	r->reconfig = match_reconfig_udp;
	r->identify = match_identify_udp;
	r->eval = match_eval_udp;
	r->cleanup = match_cleanup_udp;

	return 1;

}

int match_init_udp(struct match *m) {

	copy_params(m->params_value, match_udp_params, 1, PARAMS_NUM);

	match_undefined_id = (*m->match_register) ("undefined");

	return 1;

}

int match_reconfig_udp(struct match *m) {

	if (!m->match_priv) {
		m->match_priv = malloc(sizeof(struct match_priv_udp));
		bzero(m->match_priv, sizeof(struct match_priv_udp));
	}

	struct match_priv_udp *p = m->match_priv;
	if (sscanf(m->params_value[0], "%hu:%hu", &p->sport_min, &p->sport_max) != 2) {
		if (sscanf(m->params_value[0], "%hu", &p->sport_min)) {
			p->sport_max = p->sport_min;
		} else
			return 0;
	}
	if (sscanf(m->params_value[1], "%hu:%hu", &p->dport_min, &p->dport_max) != 2) {
		if (sscanf(m->params_value[1], "%hu", &p->dport_min)) {
			p->dport_max = p->dport_min;
		} else
			return 0;
	}

	ndprint("Match UDP : sport %u:%u, dport %u:%u\n", p->sport_min ,p->sport_max, p->dport_min , p->dport_max);

	return 1;
}

int match_identify_udp(struct layer* l, void *frame, unsigned int start, unsigned int len) {
	struct udphdr *hdr = frame + start;

	ndprint("Processing UDP packet -> SPORT : %u | DPORT %u", ntohs(hdr->uh_sport), ntohs(hdr->uh_dport));
	l->payload_size = ntohs(hdr->uh_ulen) - sizeof(struct udphdr);

	l->payload_start = start + sizeof(struct udphdr);
	l->payload_size = ntohs(hdr->uh_ulen) - sizeof(struct udphdr);
	ndprint(" | SIZE : %u\n", l->payload_size);

	return match_undefined_id;

}

int match_eval_udp(struct match* match, void *frame, unsigned int start, unsigned int len, struct layer *l) {

	struct udphdr *hdr = frame + start;

	struct match_priv_udp *mp = match->match_priv;

	unsigned short sport = ntohs(hdr->uh_sport);
	unsigned short dport = ntohs(hdr->uh_dport);
	
	
	if (sport < mp->sport_min || sport > mp->sport_max)
		return 0;
	
	if (dport < mp->dport_min || dport > mp->dport_max)
		return 0;

	return 1;


}

int match_cleanup_udp(struct match *m) {

	clean_params(m->params_value, PARAMS_NUM);

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
