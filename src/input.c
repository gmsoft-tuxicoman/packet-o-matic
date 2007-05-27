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
#include "input.h"
#include "match.h"
#include "timers.h"

struct input_reg *inputs[MAX_INPUT]; ///< Global variable which contains all the input registered in a table.
static struct input_functions i_funcs; ///< Variable to hold the function pointers passed to the input.

/**
 * This function will try to find the module input_<name>.so and
 * call the function input_<name>_register() from it.
 * This function should return the input type id on success or I_ERR on failure.
 * Subsequently, this function behave the same.
 **/
int input_register(const char *input_name) {


	int i;


	for (i = 0; i < MAX_INPUT; i++) {
		if (inputs[i] != NULL) {
			if (strcmp(inputs[i]->input_name, input_name) == 0) {
				return i;
			}
		} else {

			int (*register_my_input) (struct input_reg *, struct input_functions *);

			void *handle = NULL;
			register_my_input = lib_get_register_func("input", input_name, &handle);


			if (!register_my_input) {
				return I_ERR;
			}

			struct input_reg *my_input = malloc(sizeof(struct input_reg));
			bzero(my_input, sizeof(struct input_reg));

			i_funcs.match_register = match_register;
			
			if ((*register_my_input) (my_input, &i_funcs) != I_OK) {
				dprint("Error while loading input %s. Could not register input !\n", input_name);
				return I_ERR;
			}

			inputs[i] = my_input;
			inputs[i]->input_name = malloc(strlen(input_name) + 1);
			strcpy(inputs[i]->input_name, input_name);
			inputs[i]->dl_handle = handle;

			dprint("Input %s registered\n", input_name);


			return i;

		}

	}

	return I_ERR;

}

/**
 * Allocate and return a struct *input.
 * It calls the init function of the input module corresponding to the type of module given in input_type.
 * On failure, it returns NULL.
 **/
struct input *input_alloc(int input_type) {

	if (!inputs[input_type]) {
		dprint("Input type %u is not registered\n", input_type);
		return NULL;
	}

	struct input *i = malloc(sizeof(struct input));
	bzero(i, sizeof(struct input));

	i->type = input_type;
	
	if (inputs[input_type]->init)
		if ((*inputs[input_type]->init) (i) != I_OK) {
			free(i);
			return NULL;
		}
	
	return i;
}

/**
 * It updates the value in the input structure. It will be parsed usually when opening the input.
 * Returns I_OK on success and I_ERR on failure.
 **/
int input_set_param(struct input *i, char *name, char* value) {

	if (!inputs[i->type]->params_name)
		return I_ERR;

	int j;
	for (j = 0; inputs[i->type]->params_name[j]; j++) {
		if (!strcmp(inputs[i->type]->params_name[j], name)) {
			free(i->params_value[j]);
			i->params_value[j] = malloc(strlen(value) + 1);
			strcpy(i->params_value[j], value);
			return I_OK;
		}
	}


	return I_ERR;

}

/**
 * Returns a selectable file descriptor
 * or returns I_ERR on failure.
 **/
int input_open(struct input *i) {

	if (!i)
		return I_ERR;

	if (inputs[i->type] && inputs[i->type]->open)
		return (*inputs[i->type]->open) (i);
	return I_ERR;

}

/**
 * The buffer used should be at least 1528 bytes for ethernet and 802.1q marking. The argument bufflen is the length of the buffer.
 * Returns the number of bytes copied. Returns 0 if nothing was read and I_ERR in case of fatal error.
 **/
inline int input_read(struct input *i, struct frame *f) {

	return (*inputs[i->type]->read) (i, f);

}

/**
 * Returns I_ERR on failure.
 **/
int input_close(struct input *i) {

	if (!i)
		return I_ERR;

	if (inputs[i->type] && inputs[i->type]->close)
		return (*inputs[i->type]->close) (i);

	return I_ERR;

}

/**
 * Returns I_ERR on failure.
 **/
int input_cleanup(struct input *i) {

	if (!i)
		return I_ERR;

	if (inputs[i->type] && inputs[i->type]->cleanup)
		(*inputs[i->type]->cleanup) (i);


	free (i);
	
	return I_ERR;

}

/**
 * This function makes sure that all the memory of the input is remove.
 * However it doesn't call the cleanup() functions of the input.
 * Returns I_ERR on failure.
 **/
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

	return I_OK;

}

int input_gettimeof(struct input *i, struct timeval *tv) {

	if (!i || !inputs[i->type])
		return I_ERR;

	if (inputs[i->type]->gettimeof)
		return (*inputs[i->type]->gettimeof) (i, tv);
	
	return gettimeofday(tv, NULL);

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
