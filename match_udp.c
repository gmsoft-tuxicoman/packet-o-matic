
#include <netinet/udp.h>

#include "match_udp.h"


int match_undefined_id;

int match_register_udp(struct match_reg *r) {

	r->init = match_init_udp;
	r->config = match_config_udp;
	r->eval = match_eval_udp;
	r->cleanup = match_cleanup_udp;

	return 1;

}

int match_init_udp(struct match *m) {

	match_undefined_id = (*m->match_register) ("undefined");

	return 1;

}

int match_config_udp(struct match *m, void *params) {

	m->match_priv = params;
	return 1;
}

int match_eval_udp(struct match* match, void *frame, unsigned int start, unsigned int len) {
	struct udphdr *hdr = frame + start;

	unsigned short sport = ntohs(hdr->source);
	unsigned short dport = ntohs(hdr->dest);
	
	ndprint("Processing UDP packet -> SPORT : %u | DPORT %u\n", sport, dport);

	match->next_layer = match_undefined_id;
	match->next_start = start + sizeof(struct udphdr);

	if (!match->match_priv)
		return 1;
	
	struct match_priv_udp *mp = match->match_priv;
	
	if (sport < mp->sport_min || sport > mp->sport_max)
		return 0;
	
	if (dport < mp->dport_min || dport > mp->dport_max)
		return 0;
	
	return 1;


}

int match_cleanup_udp(struct match *m) {

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
