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



#include "input.h"

struct input_reg *inputs[MAX_INPUT];

int input_register(const char *input_name) {


	int i;


	for (i = 0; i < MAX_INPUT; i++) {
		if (inputs[i] != NULL) {
			if (strcmp(inputs[i]->input_name, input_name) == 0) {
				return i;
			}
		} else {

			int (*register_my_input) (struct input_reg *);

			void *handle = NULL;
			register_my_input = lib_get_register_func("input", input_name, &handle);


			if (!register_my_input) {
				return -1;
			}

			struct input_reg *my_input = malloc(sizeof(struct input_reg));
			bzero(my_input, sizeof(struct input_reg));

			
			if (!(*register_my_input) (my_input)) {
				dprint("Error while loading input %s. Could not register input !\n", input_name);
				return -1;
			}

			inputs[i] = my_input;
			inputs[i]->input_name = malloc(strlen(input_name) + 1);
			strcpy(inputs[i]->input_name, input_name);
			inputs[i]->dl_handle = handle;

			dprint("Input %s registered\n", input_name);


			return i;

		}

	}

	return -1;

}

struct input *input_alloc(int input_type) {

	if (!inputs[input_type]) {
		dprint("Input type %u is not registered\n", input_type);
		return NULL;
	}

	struct input *i = malloc(sizeof(struct input));
	bzero(i, sizeof(struct input));

	i->input_type = input_type;
	i->match_register = match_register;
	
	if (inputs[input_type]->init)
		if (!(*inputs[input_type]->init) (i)) {
			free(i);
			return NULL;
		}
	
	return i;
}


int input_set_param(struct input *i, char *name, char* value) {

	if (!inputs[i->input_type]->params_name)
		return 0;

	int j;
	for (j = 0; inputs[i->input_type]->params_name[j]; j++) {
		if (!strcmp(inputs[i->input_type]->params_name[j], name)) {
			free(i->params_value[j]);
			i->params_value[j] = malloc(strlen(value) + 1);
			strcpy(i->params_value[j], value);
			return 1;
		}
	}


	return 0;

}

int input_open(struct input *i) {

	if (!i)
		return 0;

	if (inputs[i->input_type] && inputs[i->input_type]->open)
		return (*inputs[i->input_type]->open) (i);
	return 1;

}

int input_get_first_layer(struct input *i) {

	return (*inputs[i->input_type]->get_first_layer) (i);

}

inline int input_read(struct input *i, unsigned char *buffer, unsigned int bufflen) {

	return (*inputs[i->input_type]->read) (i, buffer, bufflen);

}

int input_close(struct input *i) {

	if (!i)
		return 0;

	if (inputs[i->input_type] && inputs[i->input_type]->close)
		return (*inputs[i->input_type]->close) (i);

	return 1;

}

int input_cleanup(struct input *i) {

	if (!i)
		return 0;

	if (inputs[i->input_type] && inputs[i->input_type]->cleanup)
		(*inputs[i->input_type]->cleanup) (i);


	free (i);
	
	return 1;

}

int input_unregister_all() {

	int i = 0;

	for (; i < MAX_INPUT && inputs[i]; i++) {
		if (inputs[i]->params_name) {
			int j;
			for (j = 0; inputs[i]->params_name[j]; j++) {
				free(inputs[i]->params_name[j]);
				free(inputs[i]->params_help[j]);
			}
			free(inputs[i]->params_name);
			free(inputs[i]->params_help);
		}
		free(inputs[i]->input_name);
		dlclose(inputs[i]->dl_handle);
		free(inputs[i]);
		inputs[i] = NULL;

	}

	return 1;

}

void input_print_help() {

	int i, j;


	for (i = 0; inputs[i]; i++) {
		printf("* INPUT %s *\n", inputs[i]->input_name);

		if (!inputs[i]->params_name) 
			printf("No parameter for this input\n");
		else
			for (j = 0; inputs[i]->params_name[j]; j++)
				printf("%s : %s\n", inputs[i]->params_name[j], inputs[i]->params_help[j]);

		printf("\n");
	}
}
