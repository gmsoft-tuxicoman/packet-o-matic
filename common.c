/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
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

