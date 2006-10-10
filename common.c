


#include "common.h"


#ifdef DEBUG

void dprint_hex(unsigned char *str, unsigned int len) {

	int i;
	
	for (i = 0; i < len; i++)
		printf("%02X ", *(str + i));
}

#endif


unsigned int node_find_header_start(struct rule_node *node, int header_type) {
	
	if (!node) 
		return -1;
	

	struct match *m = node->match;

	if (!m)
		return -1;

	if(m->match_type == header_type) {
		// Matched the start of the packet
		return 0;
	}
	
	do {
		if(m->next_layer == header_type)
			return m->next_start;
		m = m->next;
	} while(m);

	return -1;
}

