/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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

#include "rules.h"
#include "perf.h"
// Common stuff used in modules
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <string.h>
#include <strings.h>
#include <dlfcn.h>
#include <arpa/inet.h>

// Define IPv6 fields
#if defined(__APPLE__) || defined(__darwin__) || defined(__FreeBSD__) || defined (__NetBSD__) || defined (__OpenBSD__)
#define s6_addr __u6_addr.__u6_addr8
#define s6_addr16 __u6_addr.__u6_addr16
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#if defined (__SVR4) && defined (__sun)
#define s6_addr32 _S6_un._S6_u32
#endif

#endif // __MODULES_COMMON_H__
