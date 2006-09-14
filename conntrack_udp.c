
#include <netinet/udp.h>

#include "conntrack_udp.h"

#define INITVAL 0x7513adf4

int conntrack_register_udp(struct conntrack_reg *r) {
	
	r->get_hash = conntrack_get_hash_udp;
	r->doublecheck = conntrack_doublecheck_udp;
	r->alloc_match_priv = conntrack_alloc_match_priv_udp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_udp;
	
	
	return 1;
}


__u32 conntrack_get_hash_udp(void *frame, unsigned int start) {

	struct udphdr* hdr;
	
	hdr = frame + start;	

	// Compute the hash

	__u32 udp_hash = jhash_1word((hdr->source << 16) |  hdr->dest, INITVAL);


	return udp_hash;

}

int conntrack_doublecheck_udp(void *frame, unsigned int start, void *priv) {

	

	struct udphdr* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_udp *p;
	p = priv;
	
	if (p->sport != hdr->source || p->dport != hdr->dest) {
		printf("Warning, collision detected in UDP header !!!\n");
		return 0;
	}

	return 1;
}


void *conntrack_alloc_match_priv_udp(void *frame, unsigned int start) {
	
	struct udphdr* hdr;
	hdr = frame + start;
	
	struct conntrack_priv_udp *priv;
	priv = malloc(sizeof(struct conntrack_priv_udp));
	priv->sport = hdr->source;
	priv->dport = hdr->dest;

	return priv;

}

int conntrack_cleanup_match_priv_udp(void *priv) {

	free(priv);
	return 1;
}
