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

#ifndef __COMMON_H__
#define __COMMON_H__

#include "config.h"

#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <dlfcn.h>

#include <stdio.h>
#include <stdarg.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>

#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

// Some OS don't define this (taken from GNU C)
#ifndef timercmp
#define timercmp(a, b, CMP) 						\
	(((a)->tv_sec == (b)->tv_sec) ? 				\
	((a)->tv_usec CMP (b)->tv_usec) : 				\
	((a)->tv_sec CMP (b)->tv_sec))
#endif

#ifndef timeradd
#define timeradd(a, b, result)						\
	(result)->tv_sec = (a)->tv_sec + (b)->tv_sec;			\
	(result)->tv_usec = (a)->tv_usec + (b)->tv_usec;		\
	if ((result)->tv_usec >= 1000000) {				\
		++(result)->tv_sec;					\
		(result)->tv_usec -= 1000000;				\
	}
#endif

#ifndef timersub
#define timersub(a, b, result)						\
	(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;			\
	(result)->tv_usec = (a)->tv_usec - (b)->tv_usec;		\
	if ((result)->tv_usec < 0) {					\
		--(result)->tv_sec;					\
		(result)->tv_usec += 1000000;				\
	}
#endif

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#elif HAVE_ENDIAN_H
#include <endian.h>
#else

#define LITTLE_ENDIAN	1234
#define BIG_ENDIAN	4321
#ifdef WORDS_BIGENDIAN
#define BYTE_ORDER	BIG_ENDIAN
#else
#define BYTE_ORDER	LITTLE_ENDIAN
#endif

#endif

#include "layer.h"

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#ifndef HOST_NAME_MAX
#ifdef MAXHOSTNAMELEN
#define HOST_NAME_MAX MAXHOSTNAMELEN
#else
#define HOST_NAME_MAX 255
#endif
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

/// Prepend value to log string to indicate log level
#define POM_LOG_ERR	"\1"
#define POM_LOG_WARN	"\2"
#define POM_LOG_INFO	"\3"
#define POM_LOG_DEBUG	"\4"
#define POM_LOG_TSHOOT	"\5"

/// Size of the log buffer
#define POM_LOG_BUFFER_SIZE	100

/// Console debug level
extern unsigned int console_debug_level;

/// Should we output to console
extern int console_output;

/// Log entry

struct log_entry {

	uint32_t id; // Only valid if level < POM_LOG_TSHOOT
	char file[64];
	char *data;
	char level;

	struct log_entry *prev;
	struct log_entry *next;

};

#define pom_log(args ...) pom_log_internal(__FILE__, args)

void pom_log_internal(char *file, const char *format, ...);
struct log_entry *pom_log_get_head();
struct log_entry *pom_log_get_tail();
uint32_t pom_log_get_serial();
int pom_log_rlock();
int pom_log_unlock();
int pom_log_cleanup();

int frame_alloc_aligned_buff(struct frame *f, int length);

char ** list_modules(char *type);

int uid_init();

uint32_t get_uid();

size_t base64_decode(char *output, char *input, size_t out_len);
size_t url_decode(char *output, char *input, size_t out_len);

uint64_t bswap64(uint64_t x);

#ifndef bswap16
#define bswap16(x) \
	((((x) >> 8) & 0xffu) | (((x) & 0xffu) << 8))
#endif
#ifndef bswap32
#define bswap32(x) \
	((((x) & 0xff000000u) >> 24) | (((x) & 0x00ff0000u) >>  8) | \
	(((x) & 0x0000ff00u) <<  8) | (((x) & 0x000000ffu) << 24))
#endif

#if BYTE_ORDER == BIG_ENDIAN
#define le16(x)		bswap16(x)
#define le32(x)		bswap32(x)
#define le64(x)		bswap64(x)
#define ntohll(x)	(x)
#define htonll(x)	(x)
#elif BYTE_ORDER == LITTLE_ENDIAN
#define le16(x)		(x)
#define le32(x)		(x)
#define le64(x)		(x)
#define ntohll(x)	bswap64(x)
#define htonll(x)	bswap64(x)
#else
#error "Please define byte ordering"
#endif

#endif
