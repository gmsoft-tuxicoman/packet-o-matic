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

#include "common.h"
#include "layer.h"
#include "match.h"

static struct layer** pool;
static int poolsize, poolused;


static struct layer_info* info_pool[MAX_MATCH];

int layer_init() {

	pool = NULL;
	poolused = 0;
	poolsize = 0;

	return 1;

}

struct layer* layer_pool_get() {

	struct layer *l;
	if (poolused >= poolsize) {
		pool = realloc(pool, sizeof(struct layer*) * (poolsize + 1));
		pool[poolsize] = malloc(sizeof(struct layer));
		poolsize++;
	
	}

	l = pool[poolused];
	poolused++;
	bzero(l, sizeof(struct layer));

	return l;

}

int layer_pool_discard() {
	
	poolused = 0;
	return 1;

}

int layer_info_snprintf(char *buff, int maxlen, struct layer_info *inf) {
	

	if (!inf) // Not found
		return 0;

	bzero(buff, maxlen);

	switch (inf->type) {
		
		case LAYER_INFO_STRING:
			strncpy(buff, inf->val.c, maxlen - 1);
			return strlen(buff);

		case LAYER_INFO_INT64:
			return snprintf(buff, maxlen - 1, "%li", (long) inf->val.i64);
			
		case LAYER_INFO_UINT64:
			return snprintf(buff, maxlen - 1, "%lu", (unsigned long) inf->val.ui64);

		case LAYER_INFO_DOUBLE:
			return snprintf(buff, maxlen - 1, "%f", inf->val.d);

	}

	// inf->type invalid
	
	return 0;
	
}

struct layer_info* layer_info_register(unsigned int match_type, char *name, unsigned int value_type) {

	struct layer_info* li;
	li = malloc(sizeof(struct layer_info));
	bzero(li, sizeof(struct layer_info));

	li->name = malloc(strlen(name) + 1);
	strcpy(li->name, name);

	li->type = value_type;

	// Register the infos in the order we are given
	struct layer_info *tmp = info_pool[match_type];

	if (!tmp)
		info_pool[match_type] = li;
	else {
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = li;
	}


	return li;


}


int layer_info_set_str(struct layer_info *inf, char *value) {

	inf->val.c = realloc(inf->val.c, strlen(value) + 1);
	strcpy(inf->val.c, value);
	
	return 1;

}

int layer_info_set_int64(struct layer_info *inf, int64_t value) {

	inf->val.i64 = value;
	
	return 1;
}

int layer_info_set_uint64(struct layer_info *inf, uint64_t value) {

	inf->val.ui64 = value;
	
	return 1;
}

int layer_info_set_double(struct layer_info *inf, double value) {

	inf->val.d = value;
	
	return 1;
}


int layer_cleanup() {

	int i;
	for (i = 0; i < poolsize; i++) {
		free(pool[i]);
	}
	free(pool);

	for (i = 0; i < MAX_MATCH; i++) {
		struct layer_info *inf;
		while (info_pool[i]) {
			inf = info_pool[i];
			info_pool[i] = info_pool[i]->next;
			
			free(inf->name);

			if (inf->type == LAYER_INFO_STRING)
				free(inf->val.c);

			free(inf);
		}
	}
	return 1;

}


unsigned int layer_find_start(struct layer *l, int header_type) {
	
	if (!l)
		return -1;

	do {
		if(l->type == header_type) {
			if (l->prev)
				return l->prev->payload_start;
			else
				return 0;
		}
		l = l->next;
	} while(l);

	return -1;
}

struct layer_info* layer_info_pool_get(struct layer* l) {

	return info_pool[l->type];

}


