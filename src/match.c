/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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
#include "match.h"


struct match_reg *matchs[MAX_MATCH];
static struct match_functions *m_funcs;

int match_undefined_id;


int match_register(const char *match_name) {

	int i;

	for (i = 0; i < MAX_MATCH; i++) {
		if (matchs[i] != NULL) {
			if (matchs[i]->name && strcmp(matchs[i]->name, match_name) == 0) {
				return i;
			}
		} else {
			int (*register_my_match) (struct match_reg *, struct match_functions *);

			void *handle = NULL;
			register_my_match = lib_get_register_func("match", match_name, &handle);
			
			if (!register_my_match) {
				return -1;
			}

			struct match_reg *my_match = malloc(sizeof(struct match_reg));
			bzero(my_match, sizeof(struct match_reg));

			
			matchs[i] = my_match;
			matchs[i]->name = malloc(strlen(match_name) + 1);
			strcpy(matchs[i]->name, match_name);

			my_match->type = i; // Allow the match to know it's number at registration time

			if (!(*register_my_match) (my_match, m_funcs)) {
				dprint("Error while loading match %s. Could not register match !\n", match_name);
				free(my_match->name);
				free(my_match);
				matchs[i] = NULL;
				return -1;
			}

			matchs[i]->dl_handle = handle;

			dprint("Match %s registered\n", match_name);


			return i;

		}

	}

	return -1;

}

int match_init() {

	match_undefined_id = match_register("undefined");

	m_funcs = malloc(sizeof(struct match_functions));
	m_funcs->match_register = match_register;
	m_funcs->layer_info_register = layer_info_register;

	return 1;
}

char *match_get_name(int match_type) {

	if (matchs[match_type])
		return matchs[match_type]->name;
	
	return NULL;

}


int match_get_type(const char *match_name) {

	int i;
	for (i = 0; i < MAX_MATCH && matchs[i]; i++) {
		if (strcmp(matchs[i]->name, match_name) == 0)
			return i;
	}

	return -1;
}

struct match *match_alloc(int match_type) {


	if (!matchs[match_type]) {
		dprint("Match type %u is not registered\n", match_type);
		return NULL;
	}

	struct match *m = malloc(sizeof(struct match));
	bzero(m, sizeof(struct match));

	m->type = match_type;
	
	if (matchs[match_type]->init)
		if (!(*matchs[match_type]->init) (m)) {
			free(m);
			return NULL;
		}
	return m;
}

int match_set_param(struct match *m, char *name, char *value) {

	if (!matchs[m->type]->params_name)
		return 0;

	int i;
	for (i = 0; matchs[m->type]->params_name[i]; i++) {
		if (!strcmp(matchs[m->type]->params_name[i], name)) {
			free(m->params_value[i]);
			m->params_value[i] = malloc(strlen(value) + 1);
			strcpy(m->params_value[i], value);
			if(matchs[m->type]->reconfig) {
				if (!(*matchs[m->type]->reconfig) (m)) {
					dprint("Unable to parse parameter %s (%s) for match %s\n", matchs[m->type]->params_name[i], m->params_value[i], matchs[m->type]->name);
					return 0;
				}	
			}
			return 1;
		}
	}

	dprint("No parameter %s for match %s\n", matchs[m->type]->params_name[i], matchs[m->type]->name);

	return 0;

}

inline int match_identify(struct layer *l, void* frame, unsigned int start, unsigned int len) {
	
	if (matchs[l->type]->identify)
		return (*matchs[l->type]->identify) (l, frame, start, len);

	return match_undefined_id;

}

inline int match_eval(struct match *m, void* frame, unsigned int start, unsigned int len, struct layer *l) {

	if (matchs[m->type]->eval)
		return (*matchs[m->type]->eval) (m, frame, start, len, l);
	else
		return 1;

}


int match_cleanup_module(struct match *m) {

	if (!m)
		return 0;

	if (matchs[m->type] && matchs[m->type]->cleanup)
		(*matchs[m->type]->cleanup) (m);
	

	free(m);


	return 1;

}

int match_cleanup() {

	if (m_funcs)
		free(m_funcs);
	m_funcs = NULL;

	return 1;
}


int match_unregister(unsigned int match_type) {

	struct match_reg *r = matchs[match_type];

	if (!r)
		return 0;

	if (r->unregister)
		(*r->unregister) (r);
	
	if (r->params_name) {
		int i;
		for (i = 0; r->params_name[i]; i++) {
			free(r->params_name[i]);
			free(r->params_help[i]);
		}
		free(r->params_name);
		free(r->params_help);
	}
	free(r->name);
	dlclose(r->dl_handle);
	free(r);

	matchs[match_type] = NULL;

	return 1;
}

int match_unregister_all() {

	int i = 0;

	for (; i < MAX_MATCH && matchs[i]; i++)
		match_unregister(i);

	return 1;

}

void match_print_help() {

	int i, j;


	for (i = 0; matchs[i]; i++) {
		printf("* MATCH %s *\n", matchs[i]->name);

		if (!matchs[i]->params_name) 
			printf("No parameter for this match\n");
		else
			for (j = 0; matchs[i]->params_name[j]; j++)
				printf("%s : %s\n", matchs[i]->params_name[j], matchs[i]->params_help[j]);

		printf("\n");
	}
}
