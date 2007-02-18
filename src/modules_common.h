/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __MODULES_COMMON_H__
#define __MODULES_COMMON_H__

#include "config.h"

// Common stuff used in modules
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <arpa/inet.h>

// Those two collide // TOBE REMOVED
#ifndef __COMMON_H__


#ifdef __linux__
#define __FAVOR_BSD
#ifndef __USE_BSD
#define __USE_BSD
#endif
#endif


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



#include "rules.h"

inline int mask_compare2(unsigned char *value1, unsigned char *mask1, unsigned char *value2, unsigned char *mask2, unsigned int len) {

	int i;
	
	for (i = 0; i < len; i++) 
		if ((value1[i] & mask1[i]) != (value2[i] & mask2[i]))
			return 0;
	return 1;

};


unsigned int layer_find_start(struct layer *l, int header_type) {
	
	if (!l)
		return -1;

	do {
		if(l->type == header_type) {
			if (l->prev)
				return l->prev->payload_start;
			else
				return 0;
		}
		l = l->next;
	} while(l);

	return -1;
}


#endif // __COMMON_H__
// d = dest; s = source; i = index; z = size

#define copy_params(d, s, i, z) { \
	d = malloc(sizeof(char *) * (z + 1)); \
	bzero(d, sizeof(char *) * (z + 1)); \
	int j; \
	for (j = 0; j < z; j++) { \
		d[j] = malloc(strlen(s[j][i]) + 1);\
		strcpy(d[j], s[j][i]); \
	} \
}

#define clean_params(p, s) { \
	int j; \
	for (j = 0; j < s ; j++) \
		if (p[j]) \
			free(p[j]); \
	free(p);\
}


#define mask_compare(a, b, c, d) mask_compare2(a, c, b, c, d)

#endif // __MODULES_COMMON_H__
