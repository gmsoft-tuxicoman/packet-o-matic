/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2008 Guy Martin <gmsoft@tuxicoman.be>
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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

/**
 * @defgroup layer_core Layer core functions
 */
/*@{*/

/// Maximum fields per layer
#define MAX_LAYER_FIELDS 8
/// Maximum identical layer in a frame
#define MAX_SAME_LAYERS 4

/// Pool of preallocated fields
struct layer_field_pool {

	struct ptype *pool[MAX_SAME_LAYERS][MAX_LAYER_FIELDS]; ///< Pool of fields
	unsigned int usage; ///< Current usage of the pool
	unsigned int size; ///< Current size of the pool

};

/// contains all the info of a layer
struct layer {
	struct layer *next; ///< next layer in the packet
	struct layer *prev; ///< previous layer in the packet
	int type; ///< type of this layer
	int payload_start; ///< start of the payload
	int payload_size; ///< size of the payload
	struct ptype *fields[MAX_LAYER_FIELDS]; ///< fields associated with this layer
};


/// info of a single frame

struct frame {
	struct layer* l; ///< layers of the frame
	unsigned int len; ///< length of the current frame
	unsigned int bufflen; ///< total length of the buffer
	int first_layer; ///< first layer of the frame
	struct timeval tv; ///< when the packet arrived
	struct input *input; ///< The input from where the packet comes from
	void *buff_base; ///< non aligned buffer for the frame
	void *buff; ///< the frame itself in an aligned buffer
	unsigned int align_offset; ///< Alignement offset of the buffer
	struct conntrack_entry *ce; ///< Conntrack entry associated with this packet if any

};

/// Init the layer subsystem
int layer_init();

/// Find the starting offset of a layer
int layer_find_start(struct layer *l, int header_type);

/// Get the next available layer out of the pool
struct layer* layer_pool_get();

/// Release a layer that we were using
int layer_pool_discard();

/// Get the next available layer field out of the pool
int layer_field_pool_get(struct layer* l);

/// Cleanup the layer subsystem
int layer_cleanup();

/// Parse the provided expression and save it into the buffer
int layer_field_parse(struct layer *l, char *expr, char *buff, size_t size);

/*@}*/
#endif
