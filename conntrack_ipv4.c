
#include <netinet/ip.h>

#include "conntrack_ipv4.h"

#define INITVAL 0x5fb83a0c // Random value

int conntrack_register_ipv4(struct conntrack_reg *r) {
	
	r->get_hash = conntrack_get_hash_ipv4;
	r->doublecheck = conntrack_doublecheck_ipv4;
	r->alloc_match_priv = conntrack_alloc_match_priv_ipv4;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_ipv4;
	
	
	return 1;
}


__u32 conntrack_get_hash_ipv4(void *frame, unsigned int start) {

	struct iphdr* hdr;
	
	hdr = frame + start;	

	// Compute the hash

	__u32 ipv4_hash = jhash_2words(hdr->saddr, hdr->daddr, INITVAL);


	return ipv4_hash;

}

int conntrack_doublecheck_ipv4(void *frame, unsigned int start, void *priv) {

	

	struct iphdr* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_ipv4 *p;
	p = priv;
	
	if (p->saddr != hdr->saddr || p->daddr != hdr->daddr) {
		printf("Warning, collision detected in IPV4 header !!!\n");
		return 0;
	}

	return 1;
}


void *conntrack_alloc_match_priv_ipv4(void *frame, unsigned int start) {
	
	struct iphdr* hdr;
	hdr = frame + start;
	
	struct conntrack_priv_ipv4 *priv;
	priv = malloc(sizeof(struct conntrack_priv_ipv4));
	priv->saddr = hdr->saddr;
	priv->daddr = hdr->daddr;

	return priv;

}

int conntrack_cleanup_match_priv_ipv4(void *priv) {

	free(priv);
	return 1;
}
