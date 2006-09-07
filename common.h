
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
#include <linux/types.h>
#undef __KERNEL__


#include "rules.h"


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
