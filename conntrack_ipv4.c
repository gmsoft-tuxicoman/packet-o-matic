
#include <netinet/ip.h>

#include "conntrack_ipv4.h"

#define CONNTRACK_SIZE 65536

struct ipv4_priv {

	__u32 saddr;
	__u32 daddr;

};

int conntrack_register_ipv4(struct conntrack_reg *r) {
	
	r->get_hash = conntrack_get_hash_ipv4;
	r->doublecheck = conntrack_doublecheck_ipv4;
	r->alloc_match_priv = conntrack_alloc_match_priv_ipv4;
	r->cleanup_match_priv = conntrack_cleanup_match_priv_ipv4;
	
	return 1;
}


__u32 conntrack_get_hash_ipv4(struct rule_match *m, void *frame, unsigned int len, u32 init) {

	struct iphdr* hdr;
	
	if (!m->prev) {
		dprint("Cannot get connection ID. No previous match !\n");
		return 0;
	}
	
	hdr = frame + m->prev->next_layer;	

	// Compute the hash

	__u32 id;	
	__u32 ipv4_hash = jhash_2words(hdr->saddr, hdr->daddr, init);

	id = conntrack_get_id(m->match_type, m, frame, len, ipv4_hash);

	// Check if this is a new connection
	
	struct ipv4_priv *priv;
	priv = conntrack_get_priv(id, m->match_type);

	if (!priv) {
		priv = malloc(sizeof(struct ipv4_priv));
		priv->saddr = hdr->saddr;
		priv->daddr = hdr->daddr;
		conntrack_add_priv(id, m->match_type, priv);
	}

	// Check if there is a collision
	
	if (priv->saddr != hdr->saddr || priv->daddr != hdr->daddr) {
		printf("Error, collision detected in IPV4 header !!!\n");
		return 0;
	}

	return id;
}




