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
#include "ptype.h"

static struct layer** pool;
static int poolsize, poolused;


static struct layer_field_pool field_pool[MAX_MATCH];

int layer_init() {

	pool = NULL;
	poolused = 0;
	poolsize = 0;

	return POM_OK;

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

	int i;
	for (i = 0; i < MAX_MATCH; i++)
		field_pool[i].usage = 0;
		
	return POM_OK;

}



int layer_cleanup() {

	int i;
	for (i = 0; i < poolsize; i++) {
		free(pool[i]);
	}
	free(pool);

	for (i = 0; i < MAX_MATCH; i++) {
		int j;
		for (j = 0; j < field_pool[i].size; j++) {
			int k;
			for (k = 0; k < MAX_LAYER_FIELDS && field_pool[i].pool[j][k]; k++)
				ptype_cleanup_module(field_pool[i].pool[j][k]);
		}
	}
	return POM_OK;

}


int layer_find_start(struct layer *l, int header_type) {
	
	if (!l)
		return POM_ERR;

	do {
		if(l->type == header_type) {
			if (l->prev)
				return l->prev->payload_start;
			else
				return 0;
		}
		l = l->next;
	} while(l);

	return POM_ERR;
}

int layer_field_pool_get(struct layer* l) {

	struct layer_field_pool *lfp = &field_pool[l->type];

	
	int i;

	if (lfp->usage >= lfp->size) {
		if (lfp->size >= MAX_SAME_LAYERS)
			return POM_ERR;

		lfp->size++;
		for (i = 0; i < MAX_LAYER_FIELDS; i++) {
			struct match_field_reg *field = match_get_field(l->type, i);
			if (!field)
				break;

			lfp->pool[lfp->usage][i] = ptype_alloc_from(field->type);
		}

	}

	for (i = 0; i< MAX_LAYER_FIELDS && lfp->pool[lfp->usage][i]; i++)
		l->fields[i] = lfp->pool[lfp->usage][i];

	lfp->usage++;

	return POM_OK;

}


