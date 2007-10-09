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

#ifndef __COMMON_H__
#define __COMMON_H__

#include "config.h"

#ifdef __linux__
#define __FAVOR_BSD
#ifndef __USE_BSD
#define __USE_BSD
#endif
#endif

#include <sys/types.h>
#include <arpa/inet.h>

#include <dlfcn.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

#include "layer.h"


#ifndef NAME_MAX
#define NAME_MAX 255
#endif

// Default return values
#define POM_OK 0
#define POM_ERR -1


void *lib_get_register_func(const char *type, const char *name, void **handle);

// Prepend value to log string to indicate log level
#define POM_LOG_ERR	"\1"
#define POM_LOG_WARN	"\2"
#define POM_LOG_INFO	"\3"
#define POM_LOG_DEBUG	"\4"
#define POM_LOG_TSHOOT	"\5"

/// Global debug level
unsigned int debug_level;

void pom_log(const char *format, ...);

#endif
