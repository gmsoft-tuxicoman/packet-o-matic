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
			struct layer_field *lf = field_pool[i].pool[j];

			while (lf) {
				struct layer_field* tmp = lf;
				ptype_cleanup_module(tmp->value);
				lf = lf->next;
				free(tmp);
			}
		}
		free(field_pool[i].pool);
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

struct layer_field* layer_field_pool_get(struct layer* l) {

	struct layer_field_pool *lfp = &field_pool[l->type];
	lfp->usage++;
	if (lfp->usage > lfp->size) {
		lfp->size = lfp->usage;
		lfp->pool = realloc(lfp->pool, sizeof(struct layer_field*) * lfp->size);
		lfp->pool[lfp->usage - 1] = NULL;
		struct match_field_reg *fields = match_get_fields(l->type);
		while (fields) {
			struct layer_field *tmp = malloc(sizeof(struct layer_field));
			bzero(tmp, sizeof(struct layer_field));
			tmp->type = fields;
			tmp->value = ptype_alloc_from(fields->type);
			if (!lfp->pool[lfp->usage - 1]) {
				lfp->pool[lfp->usage - 1] = tmp;
			} else {
				struct layer_field *addtmp = lfp->pool[lfp->usage - 1];
				while (addtmp->next)
					addtmp = addtmp->next;
				addtmp->next = tmp;
			}
			fields = fields->next;
		}

	}

	return lfp->pool[lfp->usage - 1];

}


