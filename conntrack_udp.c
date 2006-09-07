


#include <netinet/udp.h>

#include "conntrack_udp.h"


#define INITVAL 0x7513adf4 // Random value

struct udp_priv {

	__u16 sport;
	__u16 dport;

};

int conntrack_register_udp() {

	struct conntrack_reg r;
	r.get_id = conntrack_get_id_udp;

	return conntrack_register(&r, "udp");

}


__u32 conntrack_get_id_udp(struct rule_match *m, void *frame, unsigned int len, u32 init) {
	
	struct udphdr *hdr;

	if (!m->prev) {
		dprint("Cannot get connection ID. No previous match !\n");
		return 0;
	}

	hdr = frame + m->prev->next_start;


	// Compute the hash

	__u32 id;
	__u32 udp_hash = jhash_1word((hdr->source << 16 | hdr->dest), INITVAL);

	id = conntrack_get_id(m->match_type, m, frame, len, udp_hash);
	
	// Check if this is a new connection
	
	struct udp_priv *priv;
	priv = conntrack_get_priv(id, m->match_type);
	
	if (!priv) {
		priv = malloc(sizeof(struct udp_priv));
		priv->sport = hdr->source;
		priv->dport = hdr->dest;
		conntrack_add_priv(id, m->match_type, priv);
	}

	// Check if there is a collision
	

	if (priv->sport != hdr->source || priv->dport != hdr->dest) {
		printf("Error, collision detected in UDP header !!!\n");
		return 0;
	}
	
	return id;
}




