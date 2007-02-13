/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
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

#define LAYER_INFO_TXT		1
#define LAYER_INFO_LONG		2
#define LAYER_INFO_HEX		4
#define LAYER_INFO_FLOAT	8

struct layer_info {

	char *name;
	unsigned int type;
	union values_t {
		char *txt;
		long num;
		unsigned long hex;
		double flt;
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

struct layer* layer_poll_get();
int layer_poll_discard();

int layer_info_snprintf(char *buff, int maxlen, struct layer_info *inf);

int layer_info_set_txt(struct layer *l, char *name, char *value);
int layer_info_set_hex(struct layer *l, char *name, unsigned long value);
int layer_info_set_num(struct layer *l, char *name, long value);
int layer_info_set_float(struct layer *l, char *name, double value);
inline struct layer_info *layer_info_poll_get(struct layer *l, char *name);

int layer_cleanup();



#endif
