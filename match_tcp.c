
#include <netinet/tcp.h>

#include "match_tcp.h"

int match_undefined_id;

int match_register_tcp(struct match_reg *r) {

	r->init = match_init_tcp;
	r->config = match_config_tcp;
	r->eval = match_eval_tcp;
	r->cleanup = match_cleanup_tcp;

	return 1;

}

int match_init_tcp(struct match *m) {

	match_undefined_id = (*m->match_register) ("undefined");

	return 1;

}

int match_config_tcp(struct match *m, void *params) {

	m->match_priv = params;
	return 1;
}

int match_eval_tcp(struct match* match, void* frame, unsigned int start, unsigned int len) {

	struct tcphdr* hdr = frame + start;
	
	unsigned short sport = ntohs(hdr->source);
	unsigned short dport = ntohs(hdr->dest);

	ndprint("Processing TCP packet -> SPORT : %u | DPORT : %u", sport, dport);

	match->next_layer = match_undefined_id;
	match->next_start = start + (hdr->doff << 2);
	match->next_size = len - match->next_start;

	ndprint(" | SIZE : %u\n", match->next_size);

	if (!match->match_priv)
		return 1;
	
	struct match_priv_tcp *mp = match->match_priv;
	
	if (sport < mp->sport_min || sport > mp->sport_max)
		return 0;
	
	if (dport < mp->dport_min || dport > mp->dport_max)
		return 0;
	
	return 1;


}

int match_cleanup_tcp(struct match *m) {

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
