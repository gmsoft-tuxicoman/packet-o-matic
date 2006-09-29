
#include <netinet/tcp.h>

#include "conntrack_tcp.h"

#define INITVAL 0x84fa0b2c

int conntrack_register_tcp(struct conntrack_reg *r, struct conntrack_functions *ct_funcs) {
	
	r->get_hash = conntrack_get_hash_tcp;
	r->doublecheck = conntrack_doublecheck_tcp;
	r->alloc_match_priv = conntrack_alloc_match_priv_tcp;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_tcp;
	
	
	return 1;
}


__u32 conntrack_get_hash_tcp(void *frame, unsigned int start) {

	struct tcphdr* hdr;
	
	hdr = frame + start;	

	// Compute the hash

	__u32 tcp_hash = jhash_1word((hdr->source << 16) |  hdr->dest, INITVAL);


	return tcp_hash;

}

int conntrack_doublecheck_tcp(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce) {

	

	struct tcphdr* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_tcp *p;
	p = priv;
	
	if (p->sport != hdr->source || p->dport != hdr->dest) 
		return 0;

	return 1;
}


void *conntrack_alloc_match_priv_tcp(void *frame, unsigned int start, struct conntrack_entry *ce) {
	
	struct tcphdr* hdr;
	hdr = frame + start;
	
	struct conntrack_priv_tcp *priv;
	priv = malloc(sizeof(struct conntrack_priv_tcp));
	priv->sport = hdr->source;
	priv->dport = hdr->dest;

	return priv;

}

int conntrack_cleanup_match_priv_tcp(void *priv) {

	free(priv);
	return 1;
}