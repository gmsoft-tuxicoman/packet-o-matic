
#include <netinet/ip6.h>

#include "conntrack_ipv6.h"

#define INITVAL 0x8529fc6a // Random value

int conntrack_register_ipv6(struct conntrack_reg *r, struct conntrack_functions *ct_funcs) {
	
	r->get_hash = conntrack_get_hash_ipv6;
	r->doublecheck = conntrack_doublecheck_ipv6;
	r->alloc_match_priv = conntrack_alloc_match_priv_ipv6;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_ipv6;
	
	
	return 1;
}


__u32 conntrack_get_hash_ipv6(void *frame, unsigned int start) {

	struct ip6_hdr* hdr;
	
	hdr = frame + start;	

	// Compute the hash

	__u32 ipv6_hash = jhash(hdr->ip6_src.s6_addr32, 8, INITVAL);


	return ipv6_hash;

}

int conntrack_doublecheck_ipv6(void *frame, unsigned int start, void *priv, struct conntrack_entry *ce) {

	

	struct ip6_hdr* hdr;
	hdr = frame + start;

	// Check if there is a collision
	
	struct conntrack_priv_ipv6 *p;
	p = priv;
	
	int i;
	for (i = 0; i < 16; i++)
		if (hdr->ip6_src.s6_addr[i] != p->saddr.s6_addr[i] || hdr->ip6_dst.s6_addr[i] != p->daddr.s6_addr[i])
			return 0;

	return 1;
}


void *conntrack_alloc_match_priv_ipv6(void *frame, unsigned int start, struct conntrack_entry *ce) {
	
	struct ip6_hdr* hdr;
	hdr = frame + start;
	
	struct conntrack_priv_ipv6 *priv;
	priv = malloc(sizeof(struct conntrack_priv_ipv6));
	memcpy(priv->saddr.s6_addr, hdr->ip6_src.s6_addr, 16);
	memcpy(priv->daddr.s6_addr, hdr->ip6_dst.s6_addr, 16);

	return priv;

}

int conntrack_cleanup_match_priv_ipv6(void *priv) {

	free(priv);
	return 1;
}
