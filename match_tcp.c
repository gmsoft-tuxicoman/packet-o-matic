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


#include <netinet/tcp.h>

#include "match_tcp.h"

#define PARAMS_NUM 2

char *match_tcp_params[PARAMS_NUM][3] = {

	{ "sport", "1:65535", "source port or port range"},
	{ "dport", "1:65535", "destination port or port range"},

};


int match_undefined_id;

int match_register_tcp(struct match_reg *r) {

	copy_params(r->params_name, match_tcp_params, 0, PARAMS_NUM);
	copy_params(r->params_help, match_tcp_params, 2, PARAMS_NUM);

	r->init = match_init_tcp;
	r->reconfig = match_reconfig_tcp;
	r->identify = match_identify_tcp;
	r->eval = match_eval_tcp;
	r->cleanup = match_cleanup_tcp;

	return 1;

}

int match_init_tcp(struct match *m) {

	copy_params(m->params_value, match_tcp_params, 1, PARAMS_NUM);

	match_undefined_id = (*m->match_register) ("undefined");

	return 1;

}

int match_reconfig_tcp(struct match *m) {

	if (!m->match_priv) {
		m->match_priv = malloc(sizeof(struct match_priv_tcp));
		bzero(m->match_priv, sizeof(struct match_priv_tcp));
	}

	struct match_priv_tcp *p = m->match_priv;
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

	ndprint("Match TCP : sport %u:%u, dport %u:%u\n", p->sport_min ,p->sport_max, p->dport_min , p->dport_max);


	return 1;
}

int match_identify_tcp(struct layer* l, void* frame, unsigned int start, unsigned int len) {

	struct tcphdr* hdr = frame + start;
	
	ndprint("Processing TCP packet -> SPORT : %u | DPORT : %u", ntohs(hdr->source), ntohs(hdr->dest));

	unsigned int hdrlen = (hdr->doff << 2);
	l->payload_start = start + hdrlen;
	l->payload_size = len - hdrlen;

	ndprint(" | SIZE : %u\n", l->payload_size);

	return match_undefined_id;

}

int match_eval_tcp(struct match* match, void* frame, unsigned int start, unsigned int len, struct layer *l) {
	
	struct tcphdr* hdr = frame + start;
	
	unsigned short sport = ntohs(hdr->source);
	unsigned short dport = ntohs(hdr->dest);

	struct match_priv_tcp *mp = match->match_priv;

	ndprint("sport : min-max, value : %u-%u, %u\n", mp->sport_min, mp->sport_max, sport);
	if (sport < mp->sport_min || sport > mp->sport_max)
		return 0;

	ndprint("dport : min-max, value : %u-%u, %u\n", mp->dport_min, mp->dport_max, dport);
	if (dport < mp->dport_min || dport > mp->dport_max)
		return 0;

	
	return 1;


}

int match_cleanup_tcp(struct match *m) {

	clean_params(m->params_value, PARAMS_NUM);

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
