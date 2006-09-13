
#ifndef __MODULES_COMMON_H__
#define __MODULES_COMMON_H__


// Common stuff used in modules

#include <arpa/inet.h>


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <dlfcn.h>

#define __KERNEL__
#include <asm/types.h>
#undef __KERNEL__

// Those two collide // TOBE REMOVED
#ifndef __COMMON_H__

#ifdef DEBUG
#define dprint(x, y...) printf(x, ##y)


void dprint_hex(unsigned char *str, unsigned int len) {

	int i;
	
	for (i = 0; i < len; i++)
		printf("%02X ", *(str + i));
}


#ifdef NDEBUG
#define ndprint(x, y...) printf(x, ##y)
#define ndprint_hex(x, y) dprint_hex(x, y)
#else // NDEBUG
#define ndprint(x,y...)
#define ndprint_hex(a, b)
#endif // NDEBUG

#else // DEBUG

#define dprint(x,y...)
#define dprint_hex(x, y)
#define ndprint(a,b...)
#define ndprint_hex(c, d)


#endif // DEBUG

#endif // __COMMON_H__


#include "rules.h"

inline int mask_compare2(unsigned char *value1, unsigned char *mask1, unsigned char *value2, unsigned char *mask2, unsigned int len) {

	int i;
	
	for (i = 0; i < len; i++) 
		if ((value1[i] & mask1[i]) != (value2[i] & mask2[i]))
			return 0;
	return 1;

};


int node_find_header_start(struct rule_node *node, int header_type) {
	
	if (!node) 
		return -1;
	

	struct match *m = node->match;
	if (!m) {
		return -1;
	}

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



#define mask_compare(a, b, c, d) mask_compare2(a, c, b, c, d)


#endif // __MODULES_COMMON_H__
