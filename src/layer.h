/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __LAYER_H__
#define __LAYER_H__

#include <stdint.h>

#define LAYER_INFO_TYPE_MASK	0x00ff
#define LAYER_INFO_TYPE_INT32	0x0001
#define LAYER_INFO_TYPE_UINT32	0x0002
#define LAYER_INFO_TYPE_INT64	0x0003
#define LAYER_INFO_TYPE_UINT64	0x0004
#define LAYER_INFO_TYPE_DOUBLE	0x0005
#define LAYER_INFO_TYPE_STRING	0x0006
#define LAYER_INFO_TYPE_CUSTOM	0x0007

#define LAYER_INFO_PRINT_DFLT	0x0000
#define LAYER_INFO_PRINT_HEX	0x0100
#define LAYER_INFO_PRINT_ZERO	0x1000


union layer_info_val_t {
	char *c;
	int32_t i32;
	uint32_t ui32;
	int64_t i64;
	uint64_t ui64;
	double d;
};

struct layer_info {

	char *name;
	unsigned int flags;
	union layer_info_val_t val;
	struct layer_info *next;

	int (*snprintf) (char *buff, unsigned int len, struct layer_info *inf);

};

struct layer {
	struct layer *next;
	struct layer *prev;
	int type;
	unsigned int payload_start;
	unsigned int payload_size;

	struct layer_info *infos;
};


int layer_init();

unsigned int layer_find_start(struct layer *l, int header_type);

struct layer* layer_pool_get();
int layer_pool_discard();

struct layer_info* layer_info_register(unsigned int match_type, char *name, unsigned int flags);

int layer_info_snprintf(char *buff, unsigned int maxlen, struct layer_info *inf);

struct layer_info* layer_info_pool_get(struct layer* l);

int layer_cleanup();



#endif
