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


#include "common.h"
#include "match.h"


struct match_reg *matchs[MAX_MATCH];

int match_undefined_id;

int match_register(const char *match_name) {

	int i;

	for (i = 0; i < MAX_MATCH; i++) {
		if (matchs[i] != NULL) {
			if (strcmp(matchs[i]->match_name, match_name) == 0) {
				return i;
			}
		} else {
			void *handle;
			char name[NAME_MAX];
			strcpy(name, "match_");
			strcat(name, match_name);
			strcat(name, ".so");

			handle = dlopen(name, RTLD_NOW);

			if (!handle) {
				dprint("Unable to load match %s : ", match_name);
				dprint(dlerror());
				dprint("\n");
				return -1;
			}
			dlerror();

			strcpy(name, "match_register_");
			strcat(name, match_name);

			int (*register_my_match) (struct match_reg *);

			
			register_my_match = dlsym(handle, name);
			if (!register_my_match) {
				dprint("Error when finding symbol %s. Could not load match !\n", match_name);
				return -1;
			}

			struct match_reg *my_match = malloc(sizeof(struct match_reg));
			bzero(my_match, sizeof(struct match_reg));

			
			if (!(*register_my_match) (my_match)) {
				dprint("Error while loading match %s. Could not load match !\n", match_name);
				free(my_match);
				return -1;
			}

			matchs[i] = my_match;
			matchs[i]->match_name = malloc(strlen(match_name) + 1);
			strcpy(matchs[i]->match_name, match_name);
			matchs[i]->dl_handle = handle;

			dprint("Match %s registered with id %u\n", match_name, i);


			return i;

		}

	}

	return -1;

}

int match_init() {

	match_undefined_id = match_register("undefined");

	return 1;
}

int match_get_type(const char *match_name) {

	int i;
	for (i = 0; i < MAX_MATCH && matchs[i]; i++) {
		if (strcmp(matchs[i]->match_name, match_name) == 0)
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

	m->match_type = match_type;
	m->match_register = match_register;
	
	if (matchs[match_type]->init)
		if (!(*matchs[match_type]->init) (m)) {
			free(m);
			return NULL;
		}
	return m;
}

int match_set_param(struct match *m, char *name, char *value) {

	if (!matchs[m->match_type]->params_name)
		return 0;

	int i;
	for (i = 0; matchs[m->match_type]->params_name[i]; i++) {
		if (!strcmp(matchs[m->match_type]->params_name[i], name)) {
			free(m->params_value[i]);
			m->params_value[i] = malloc(strlen(value) + 1);
			strcpy(m->params_value[i], value);
			if(matchs[m->match_type]->reconfig)
				return (*matchs[m->match_type]->reconfig) (m);
			return 1;
		}
	}

	return 0;

}

inline int match_identify(struct layer *l, void* frame, unsigned int start, unsigned int len) {
	
	if (matchs[l->type]->identify)
		return (*matchs[l->type]->identify) (l, frame, start, len);

	return match_undefined_id;

}

inline int match_eval(struct match *m, void* frame, unsigned int start, unsigned int len, struct layer *l) {
	
	return (*matchs[m->match_type]->eval) (m, frame, start, len, l);

}


int match_cleanup(struct match *m) {

	if (!m)
		return 0;

	if (matchs[m->match_type] && matchs[m->match_type]->cleanup)
		(*matchs[m->match_type]->cleanup) (m);
	

	free(m);

	return 1;

}

int match_unregister_all() {

	int i = 0;

	for (; i < MAX_MATCH && matchs[i]; i++) {
		if (matchs[i]->params_name) {
			int j;
			for (j = 0; matchs[i]->params_name[j]; j++) {
				free(matchs[i]->params_name[j]);
				free(matchs[i]->params_help[j]);
			}
			free(matchs[i]->params_name);
			free(matchs[i]->params_help);
		}
		free(matchs[i]->match_name);
		dlclose(matchs[i]->dl_handle);
		free(matchs[i]);
		matchs[i] = NULL;

	}

	return 1;

}

void match_print_help() {

	int i, j;


	for (i = 0; matchs[i]; i++) {
		printf("* MATCH %s *\n", matchs[i]->match_name);

		if (!matchs[i]->params_name) 
			printf("No parameter for this match\n");
		else
			for (j = 0; matchs[i]->params_name[j]; j++)
				printf("%s : %s\n", matchs[i]->params_name[j], matchs[i]->params_help[j]);

		printf("\n");
	}
}
