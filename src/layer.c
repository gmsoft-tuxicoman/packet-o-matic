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

#include <regex.h>

#include "common.h"
#include "layer.h"
#include "match.h"
#include "ptype.h"

static struct layer** pool;
static int poolsize, poolused;

regex_t parse_regex;

static struct layer_field_pool field_pool[MAX_MATCH];

int layer_init() {

	pool = NULL;
	poolused = 0;
	poolsize = 0;

	char *exp = "\\${[a-zA-Z0-9]*\\.[a-zA-Z0-9]*}";

	if (regcomp(&parse_regex, exp, REG_ICASE)) {
		pom_log(POM_LOG_ERR "Unable to compile regex for layer parsing\r\n");
		return POM_ERR;
	}

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

	regfree(&parse_regex);

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

int layer_field_parse(struct layer *l, char *expr, char *buff, size_t size) {

	regmatch_t pmatch;

	if (regexec(&parse_regex, expr, 1, &pmatch, 0)) {
		strncpy(buff, expr, size);
		return POM_OK;
	}

	bzero(buff, size);

	int pos = 0;
	do {
		if (size < strlen(buff) + pmatch.rm_so)
			break;
		strncat(buff, expr + pos, pmatch.rm_so);
		size_t len = pmatch.rm_eo - pmatch.rm_so;
		char *expr_start = expr + pos + pmatch.rm_so + 2;
		char *match = malloc(len);
		bzero(match, len);
		strncpy(match, expr_start, len - 3);
		char *expr_sep = index(match, '.');
		*expr_sep = 0;
		expr_sep++;

		int found = 0;
		
		struct layer *tmpl = l;
		while (tmpl) {
			if (!strcmp(match, match_get_name(tmpl->type))) {
				int i;
				for (i = 0; i < MAX_LAYER_FIELDS; i++) {
					struct match_field_reg *field = match_get_field(tmpl->type, i);
					if (!strcmp(field->name, expr_sep)) {
						char vbuff[1024];
						bzero(vbuff, sizeof(vbuff));
						ptype_print_val(tmpl->fields[i], vbuff, sizeof(vbuff) - 1);
						pom_log(POM_LOG_TSHOOT "Matched %s.%s -> %s\r\n", match, expr_sep, vbuff);
						found = 1;
						if (size < strlen(buff) + strlen(vbuff))
							break;
						strcat(buff, vbuff);
						break;
					}
				}
				break;
			}
			tmpl = tmpl->next;
		}
		if (!found) {
			if (size < strlen(buff) + strlen(expr_start) + strlen(expr_sep) + 1) {
				strcat(buff, expr_start);
				strcat(buff, ".");
				strcat(buff, expr_sep);
			}
		}

		free(match);
		pos += pmatch.rm_eo;
	} while (!regexec(&parse_regex, expr + pos, 1, &pmatch, 0));
	
	if (size > strlen(buff) + strlen(expr + pos))
		strcat(buff, expr + pos);

	return POM_OK;

}
