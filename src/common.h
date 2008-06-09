/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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

#include "config.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <dlfcn.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>

#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif


#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#elif HAVE_ENDIAN_H
#include <endian.h>
#endif


#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
#ifndef __BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif


#include "layer.h"


#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#if ! defined HOST_NAME_MAX && defined MAXHOSTNAMELEN
#define HOST_NAME_MAX MAXHOSTNAMELEN
#endif

// Default return values
#define POM_OK 0
#define POM_ERR -1

// Flags used when loading libraries
#ifdef RTLD_GROUP
#define RTLD_FLAGS RTLD_NOW | RTLD_LOCAL | RTLD_GROUP
#else
#define RTLD_FLAGS RTLD_NOW | RTLD_LOCAL
#endif

void *lib_get_register_func(const char *type, const char *name, void **handle);

// Prepend value to log string to indicate log level
#define POM_LOG_ERR	"\1"
#define POM_LOG_WARN	"\2"
#define POM_LOG_INFO	"\3"
#define POM_LOG_DEBUG	"\4"
#define POM_LOG_TSHOOT	"\5"

/// Global debug level
unsigned int debug_level;

/// Should we output to console
int console_output;

void pom_log(const char *format, ...);

int frame_alloc_aligned_buff(struct frame *f, int length);

char ** list_modules(char *type);

#endif
