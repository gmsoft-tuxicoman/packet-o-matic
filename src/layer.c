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

static struct layer** poll;
static int pollsize, pollused;


int layer_init() {

	poll = NULL;
	pollused = 0;
	pollsize = 0;

	return 1;

}

struct layer* layer_poll_get() {

	struct layer *l;
	if (pollused >= pollsize) {
		poll = realloc(poll, sizeof(struct layer*) * (pollsize + 1));
		poll[pollsize] = malloc(sizeof(struct layer));
		// We create at least one info entry
		struct layer_info *inf = malloc(sizeof(struct layer_info));
		bzero(inf, sizeof(struct layer_info));
		poll[pollsize]->infos = inf;
		pollsize++;
	
	}

	l = poll[pollused];
	pollused++;
	struct layer_info *inf = l->infos;
	bzero(l, sizeof(struct layer));
	l->infos = inf;

	return l;

}

int layer_poll_discard() {
	
	int i;

	for (i = 0; i < pollused; i++) {
		struct layer *l = poll[i];
		struct layer_info *inf = l->infos;
		while (inf) {
			if (inf->val.txt && inf->type == LAYER_INFO_TXT)
				free(inf->val.txt);
			inf->name = NULL;
			inf->type = 0;
			inf = inf->next;
		}

	}

	pollused = 0;
	return 1;

}

// layer_type == match_type
int layer_info_snprintf(char *buff, int maxlen, struct layer_info *inf) {
	

	if (!inf) // Not found
		return 0;

	bzero(buff, maxlen);

	switch (inf->type) {
		
		case LAYER_INFO_TXT:
			strncpy(buff, inf->val.txt, maxlen - 1);
			return strlen(buff);

		case LAYER_INFO_LONG:
			return snprintf(buff, maxlen - 1, "%ld", inf->val.num);
			
		case LAYER_INFO_HEX:
			return snprintf(buff, maxlen - 1, "0x%lx", inf->val.hex);

		case LAYER_INFO_FLOAT:
			return snprintf(buff, maxlen - 1, "%f", inf->val.flt);

	}

	// inf->type invalid
	
	return 0;
	
}

int layer_info_set_txt(struct layer *l, char *name, char *value) {

	struct layer_info *inf = layer_info_poll_get(l, name);
	
	inf->type = LAYER_INFO_TXT;
	inf->val.txt = malloc(strlen(value) + 1);
	strcpy(inf->val.txt, value);
	
	return 1;

}

int layer_info_set_num(struct layer *l, char *name, long value) {

	struct layer_info *inf = layer_info_poll_get(l, name);
	
	inf->type = LAYER_INFO_LONG;
	inf->val.num = value;
	
	return 1;
}

int layer_info_set_hex(struct layer *l, char *name, unsigned long value) {

	struct layer_info *inf = layer_info_poll_get(l, name);
	
	inf->type = LAYER_INFO_HEX;
	inf->val.hex = value;
	
	return 1;
}

int layer_info_set_float(struct layer *l, char *name, double value) {

	struct layer_info *inf = layer_info_poll_get(l, name);
	
	inf->type = LAYER_INFO_FLOAT;
	inf->val.flt = value;
	
	return 1;
}


inline struct layer_info *layer_info_poll_get(struct layer *l, char *name) {
	
	struct layer_info *inf = l->infos;

	while (inf->name) {
		if (!inf->next) {
			inf->next = malloc(sizeof(struct layer_info));
			bzero(inf->next, sizeof(struct layer_info));
		}
		inf = inf->next;
	}
	
	inf->name = name;

	return inf;

}

int layer_cleanup() {

	int i;
	for (i = 0; i < pollsize; i++) {
		struct layer_info *inf;
		while (poll[i]->infos) {
			inf = poll[i]->infos;
			poll[i]->infos = poll[i]->infos->next;
			
			if (inf->type == LAYER_INFO_TXT)
				free(inf->val.txt);

			free(inf);
		}
		free(poll[i]);
	}
	free(poll);
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

