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

struct layer_field {

	struct match_field_reg *type;
	struct ptype *value;

	struct layer_field *next;

};

struct layer_field_pool {

	struct layer_field **pool;
	unsigned int usage;
	unsigned int size;

};

/// contains all the info of a layer
struct layer {
	struct layer *next; ///< next layer in the packet
	struct layer *prev; ///< previous layer in the packet
	int type; ///< type of this layer
	int payload_start; ///< start of the payload
	int payload_size; ///< size of the payload
	struct layer_field *fields; ///< fields associated with this layer
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

int layer_find_start(struct layer *l, int header_type);

struct layer* layer_pool_get();
int layer_pool_discard();

struct layer_field* layer_field_pool_get(struct layer* l);

int layer_cleanup();



#endif
