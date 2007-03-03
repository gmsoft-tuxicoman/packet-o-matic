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

#define LAYER_INFO_INT64		0x0001
#define LAYER_INFO_UINT64		0x0002
#define LAYER_INFO_DOUBLE		0x0004
#define LAYER_INFO_STRING		0x0008


struct layer_info {

	char *name;
	unsigned int type;
	union values_t {
		char *c;
		int64_t i64;
		uint64_t ui64;
		double d;
	} val;

	struct layer_info *next;

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

struct layer_info* layer_info_register(unsigned int match_type, char *name, unsigned int value_type);

int layer_info_snprintf(char *buff, int maxlen, struct layer_info *inf);

int layer_info_set_int64(struct layer_info *inf, int64_t value);
int layer_info_set_uint64(struct layer_info *inf, uint64_t value);
int layer_info_set_double(struct layer_info *inf, double value);
int layer_info_set_str(struct layer_info *inf, char *value);

struct layer_info* layer_info_pool_get(struct layer* l);

int layer_cleanup();



#endif
