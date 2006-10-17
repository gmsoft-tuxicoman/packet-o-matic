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

#ifndef __COMMON_H__
#define __COMMON_H__

// Common stuff used everywhere

#include <arpa/inet.h>

#include <dlfcn.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define __KERNEL__ // we need u32 definition for <linux/jhash.h>
#include <asm/types.h>
#undef __KERNEL__


#include "rules.h"

unsigned int node_find_header_start(struct rule_node *node, int header_type);

#ifdef DEBUG
#define dprint(x, y...) printf(x, ##y)


void dprint_hex(unsigned char *str, unsigned int len);

#ifdef NDEBUG
#define ndprint(x, y...) printf(x, ##y)
#define ndprint_hex(x, y) dprint_hex(x, y)
#else
#define ndprint(x,y...)
#define ndprint_hex(a, b)
#endif

#else

#define dprint(x,y...)
#define dprint_hex(x, y)
#define ndprint(a,b...)
#define ndprint_hex(c, d)


#endif


#endif
