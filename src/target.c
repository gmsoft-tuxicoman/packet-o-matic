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


#include "target.h"
#include "input.h"
#include "conntrack.h"

#define MAX_TARGET 16


struct target_reg *targets[MAX_TARGET];
struct target_functions *tg_funcs;

int target_init() {

	tg_funcs = malloc(sizeof(struct target_functions));
	tg_funcs->match_register = match_register;
	tg_funcs->conntrack_add_priv = conntrack_add_target_priv;
	tg_funcs->conntrack_get_priv = conntrack_get_target_priv;
	tg_funcs->layer_info_snprintf = layer_info_snprintf;
	tg_funcs->match_get_name = match_get_name;

	dprint("Targets initialized\n");

	return 1;

}

int target_register(const char *target_name) {

	int i;

	
	for (i = 0; i < MAX_TARGET; i++) {
		if (targets[i] != NULL) {
			if (strcmp(targets[i]->target_name, target_name) == 0) {
				return i;
			}
		} else {
			int (*register_my_target) (struct target_reg *, struct target_functions *);

			void *handle = NULL;
			register_my_target = lib_get_register_func("target", target_name, &handle);

			if (!register_my_target) {
				return -1;
			}

			struct target_reg *my_target = malloc(sizeof(struct target_reg));
			bzero(my_target, sizeof(struct target_reg));

			
			if (!(*register_my_target) (my_target, tg_funcs)) {
				dprint("Error while loading target %s. could not register target !\n", target_name);
				return -1;
			}


			targets[i] = my_target;
			targets[i]->target_name = malloc(strlen(target_name) + 1);
			strcpy(targets[i]->target_name, target_name);
			targets[i]->dl_handle = handle;

			dprint("Target %s registered\n", target_name);
			
			return i;
		}
	}


	return -1;

}


struct target *target_alloc(int target_type) {

	if (!targets[target_type]) {
		dprint("Target type %u is not registered\n", target_type);
		return NULL;
	}
	struct target *t = malloc(sizeof(struct target));
	bzero(t, sizeof(struct target));

	t->target_type = target_type;
	
	if (targets[target_type]->init)
		if (!(*targets[target_type]->init) (t)) {
			free(t);
			return NULL;
		}
		
	return t;
}

int target_set_param(struct target *t, char *name, char* value) {

	if (!targets[t->target_type]->params_name)
		return 0;

	int i;
	for (i = 0; targets[t->target_type]->params_name[i]; i++) {
		if (!strcmp(targets[t->target_type]->params_name[i], name)) {
			free(t->params_value[i]);
			t->params_value[i] = malloc(strlen(value) + 1);
			strcpy(t->params_value[i], value);
			return 1;
		}
	}


	return 0;

}

int target_open(struct target *t) {

	if (!t)
		return 0;

	if (targets[t->target_type] && targets[t->target_type]->open)
		return (*targets[t->target_type]->open) (t);
	return 1;

}

int target_process(struct target *t, struct frame *f) {

	if (targets[t->target_type]->process)
		return (*targets[t->target_type]->process) (t, f);
	return 1;

}

int target_close(struct target *t) {

	if (!t)
		return 1;

	if (targets[t->target_type] && targets[t->target_type]->close)
		return (*targets[t->target_type]->close) (t);
	return 1;

}

int target_cleanup_t(struct target *t) {

	if (!t)
		return 1;

	if (targets[t->target_type] && targets[t->target_type]->cleanup)
		(*targets[t->target_type]->cleanup) (t);
	
	free (t);

	return 1;

}

int target_unregister_all() {

	int i = 0;

	for (; i < MAX_INPUT && targets[i]; i++) {
		if (targets[i]->params_name) {
			int j;
			for (j = 0; targets[i]->params_name[j]; j++) {
				free(targets[i]->params_name[j]);
				free(targets[i]->params_help[j]);
			}
			free(targets[i]->params_name);
			free(targets[i]->params_help);
		}
		free(targets[i]->target_name);
		dlclose(targets[i]->dl_handle);
		free(targets[i]);
		targets[i] = NULL;

	}

	return 1;

}

int target_cleanup() {

	free(tg_funcs);

	return 1;

}


void target_print_help() {

	int i, j;


	for (i = 0; targets[i]; i++) {
		printf("* TARGET %s *\n", targets[i]->target_name);

		if (!targets[i]->params_name) 
			printf("No parameter for this target\n");
		else
			for (j = 0; targets[i]->params_name[j]; j++)
				printf("%s : %s\n", targets[i]->params_name[j], targets[i]->params_help[j]);

		printf("\n");
	}
}
