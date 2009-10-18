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

#include <regex.h>

#include "common.h"
#include "layer.h"
#include "match.h"
#include "ptype.h"

static struct layer** pool;
static int poolsize, poolused;

static regex_t parse_regex;

static struct layer_field_pool field_pool[MAX_MATCH];

/**
 * @return POM_OK on success, POM_ERR on failure.
 */
int layer_init() {

	pool = NULL;
	poolused = 0;
	poolsize = 0;

	char *exp = "\\${[a-zA-Z0-9]*\\.[a-zA-Z0-9]*}";

	if (regcomp(&parse_regex, exp, REG_ICASE)) {
		pom_log(POM_LOG_ERR "Unable to compile regex for layer parsing");
		return POM_ERR;
	}

	return POM_OK;

}

/**
 * @return The next available layer or NULL on error.
 */
struct layer* layer_pool_get() {

	struct layer *l;
	if (poolused >= poolsize) {
		pool = realloc(pool, sizeof(struct layer*) * (poolsize + 1));
		pool[poolsize] = malloc(sizeof(struct layer));
		poolsize++;
	
	}

	l = pool[poolused];
	poolused++;
	memset(l, 0, sizeof(struct layer));

	return l;

}

/**
 * @return POM_OK on success, POM_ERR on failure.
 */
int layer_pool_discard() {
	
	poolused = 0;

	int i;
	for (i = 0; i < MAX_MATCH; i++)
		field_pool[i].usage = 0;
		
	return POM_OK;

}


/**
 * @return POM_OK on success, POM_ERR on failure.
 */
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
				ptype_cleanup(field_pool[i].pool[j][k]);
		}
	}

	regfree(&parse_regex);

	return POM_OK;

}

/**
 * @param l List of layers
 * @param header_type Layer to find in the list
 * @return Offset of the given layer in the packet
 */
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

/**
 * @param l Layer to get a field for
 * @return POM_OK on success, POM_ERR on failure.
 */
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

/**
 * @param l List of layers to use for replacing parsed values
 * @param expr Expression to parse
 * @param buff Preallocated buffer to save the result
 * @param size Size of the preallocated buffer
 * @return POM_OK on success, POM_ERR on failure.
 */
int layer_field_parse(struct layer *l, char *expr, char *buff, size_t size) {

	regmatch_t pmatch;

	if (regexec(&parse_regex, expr, 1, &pmatch, 0)) {
		strncpy(buff, expr, size);
		return POM_OK;
	}

	memset(buff, 0, size);

	int pos = 0;
	do {
		if (size < strlen(buff) + pmatch.rm_so)
			break;
		strncat(buff, expr + pos, pmatch.rm_so);
		size_t len = pmatch.rm_eo - pmatch.rm_so;
		char *expr_start = expr + pos + pmatch.rm_so + 2;
		char *match = malloc(len);
		memset(match, 0, len);
		strncpy(match, expr_start, len - 3);
		char *expr_sep = strchr(match, '.');
		*expr_sep = 0;
		expr_sep++;

		int found = 0;
		
		struct layer *tmpl = l;
		while (tmpl) {
			if (!strcmp(match, match_get_name(tmpl->type))) {
				int i;
				for (i = 0; i < MAX_LAYER_FIELDS; i++) {
					struct match_field_reg *field = match_get_field(tmpl->type, i);
					if (!field)
						break;
					if (!strcmp(field->name, expr_sep)) {
						char vbuff[1024];
						memset(vbuff, 0, sizeof(vbuff));
						ptype_print_val(tmpl->fields[i], vbuff, sizeof(vbuff) - 1);
						pom_log(POM_LOG_TSHOOT "Matched %s.%s -> %s", match, expr_sep, vbuff);
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
			if (strlen(buff) + strlen(match) + strlen(expr_sep) + 1 < size) {
				strcat(buff, match);
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


