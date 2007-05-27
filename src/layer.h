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

#include "config.h"

#include <stdint.h>
#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif



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

/// a info can have multiple values
union layer_info_val_t {
	char *c; ///< used with LAYER_INFO_TYPE_STRING or LAYER_INFO_TYPE_CUSTOM
	int32_t i32; ///< used with LAYER_INFO_TYPE_INT32
	uint32_t ui32; ///< used with LAYER_INFO_TYPE_UINT32
	int64_t i64; ///< used with LAYER_INFO_TYPE_INT64
	uint64_t ui64; ///< used with LAYER_INFO_TYPE_UINT64
	double d; ///< used with LAYER_INFO_TYPE_DOUBLE
};

/// save info about a particular info of a layer
struct layer_info {

	char *name; ///< name of the info
	unsigned int flags; ///< flags used when displaying it
	union layer_info_val_t val; ///< value
	struct layer_info *next; ///< next info for this layer

	int (*snprintf) (char *buff, unsigned int len, struct layer_info *inf); ///< custom snprintf function for this info

};


/// contains all the info of a layer
struct layer {
	struct layer *next; ///< next layer in the packet
	struct layer *prev; ///< previous layer in the packet
	int type; ///< type of this layer
	unsigned int payload_start; ///< start of the payload
	unsigned int payload_size; ///< size of the payload
	struct layer_info *infos; ///< infos associated with this layer
};


/// info of a single frame

struct frame {
	struct layer* l; ///< layers of the frame
	unsigned int len; ///< length of the current frame
	unsigned int bufflen; ///< total length of the buffer
	int first_layer; ///< first layer of the frame
	struct timeval tv; ///< when the packet arrived
	struct input *input; ///< The input from where the packet comes from
	void *buff; ///< the frame itself
	struct conntrack_entry *ce; ///< Conntrack entry associated with this packet if any

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
