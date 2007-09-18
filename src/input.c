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
#include "ptype.h"

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
			if (strcmp(inputs[i]->name, input_name) == 0) {
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
			my_input->type = i;
			inputs[i] = my_input;
			inputs[i]->dl_handle = handle;

			i_funcs.match_register = match_register;
			i_funcs.register_mode = input_register_mode;
			i_funcs.register_param = input_register_param;
			i_funcs.ptype_alloc = ptype_alloc;
			i_funcs.ptype_cleanup = ptype_cleanup_module;
			i_funcs.ptype_snprintf = ptype_print_val;
			
			if ((*register_my_input) (my_input, &i_funcs) != I_OK) {
				dprint("Error while loading input %s. Could not register input !\n", input_name);
				inputs[i] = NULL;
				free(my_input);
				return I_ERR;
			}

			inputs[i] = my_input;
			inputs[i]->name = malloc(strlen(input_name) + 1);
			strcpy(inputs[i]->name, input_name);
			inputs[i]->dl_handle = handle;

			dprint("Input %s registered\n", input_name);


			return i;

		}

	}

	return I_ERR;

}

/**
 * Allocate a mode to an input and associate it with it.
 * The first registered mode will be the default mode.
 * Return the allocated mode for reference. On failure returns NULL.
 **/

struct input_mode *input_register_mode(int input_type, const char *name, const char *descr) {

	if (!inputs[input_type])
		return NULL;
	
	struct input_mode *mode = malloc(sizeof(struct input_mode));
	bzero(mode, sizeof(struct input_mode));
	
	mode->name = malloc(strlen(name) + 1);
	strcpy(mode->name, name);
	mode->descr = malloc(strlen(descr) + 1);
	strcpy(mode->descr, descr);

	mode->next = inputs[input_type]->modes;
	inputs[input_type]->modes = mode;

	if (!inputs[input_type]->default_mode)
		inputs[input_type]->default_mode = mode;

	return mode;

}

/**
 * Set the current input mode.
 * Return I_ERR if the mode doesn't exists or if the input is already running
 **/

int input_set_mode(struct input *i, char *mode_name) {
	if (!i)
		return I_ERR;
	if (i->running)
		return I_ERR;
	struct input_mode *mode = inputs[i->type]->modes;
	while (mode) {
		if (!strcmp(mode->name, mode_name)) {
			i->mode = mode;
			return I_OK;
		}
		mode = mode->next;
	}

	return I_ERR;

 }

/**
 * Register a parameter for a specific input mode.
 * Returns I_ERR on failure, I_OK on success.
 **/
int input_register_param(struct input_mode *mode, char *name, char *defval, struct ptype *value, char *descr) {

	if (!mode)
		return I_ERR;

	struct input_param *param = malloc(sizeof(struct input_param));
	bzero(param, sizeof(struct input_param));

	param->name = malloc(strlen(name) + 1);
	strcpy(param->name, name);
	param->defval = malloc(strlen(name) + 1);
	strcpy(param->defval, defval);
	param->descr = malloc(strlen(descr) + 1);
	strcpy(param->descr, descr);
	param->value = value;

	if (ptype_parse_val(param->value, defval) == P_ERR)
		return I_ERR;

	if (!mode->params) {
		mode->params = param;
	} else {
		struct input_param *tmp = mode->params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = param;
	}

	return I_OK;
}

/**
 * Return the name of the input.
 **/
char *input_get_name(int input_type) {
	if (!inputs[input_type])
		return NULL;
	
	return inputs[input_type]->name;
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
 * Returns a selectable file descriptor
 * or returns I_ERR on failure.
 **/
int input_open(struct input *i) {

	if (!i)
		return I_ERR;

	if (i->running)
		return I_ERR;

	if (inputs[i->type] && inputs[i->type]->open) {
		int res = (*inputs[i->type]->open) (i);
		if (res == I_ERR)
			return I_ERR;
	}

	i->running = 1;
	return I_OK;
}

/**
 * The buffer used should be at least the size of the snaplen returned by input_get_caps. The argument bufflen is the length of the buffer.
 * Returns the number of bytes copied. Returns 0 if nothing was read and I_ERR in case of fatal error.
 **/
int input_read(struct input *i, struct frame *f) {

	int res = (*inputs[i->type]->read) (i, f);
	if (res == I_ERR) {
		input_close(i);
		return I_ERR;
	}
	return res;
}

/**
 * Returns I_ERR on failure.
 **/
int input_close(struct input *i) {

	if (!i)
		return I_ERR;
	
	if (!i->running)
		return I_ERR;
	
	i->running = 0;

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
 * Return I_ERR on failure.
 **/

int input_unregister(int input_type) {
	
	if (!inputs[input_type])
		return I_ERR;

	if (inputs[input_type]->unregister)
		(*inputs[input_type]->unregister) (inputs[input_type]);
	
	struct input_mode *m = inputs[input_type]->modes;
	while (m) {
		struct input_param *p = m->params;
		while (p) {
			free(p->name);
			free(p->defval);
			free(p->descr);
			p = p->next;
			free(m->params);
			m->params = p;
		}
		free(m->name);
		free(m->descr);
		m = m->next;
		free(inputs[input_type]->modes);
		inputs[input_type]->modes = m;
	}
	if (dlclose(inputs[input_type]->dl_handle))
		dprint("Error while closing library of input %s\n", inputs[input_type]->name);
	free(inputs[input_type]->name);
	free(inputs[input_type]);
	inputs[input_type] = NULL;
	return I_OK;
}

/**
 * This function makes sure that all the memory of the input is remove.
 * However it doesn't call the cleanup() functions of the input.
 * Returns I_ERR on failure.
 **/
int input_unregister_all() {

	int i = 0;

	for (; i < MAX_INPUT && inputs[i]; i++) 
		input_unregister(i);
	return I_OK;

}

int input_getcaps(struct input *i, struct input_caps *ic) {

	if (!i || !inputs[i->type])
		return I_ERR;

	return (*inputs[i->type]->getcaps) (i, ic);
	

}


void input_print_help() {

	int i;


	for (i = 0; inputs[i]; i++) {
		printf("* INPUT %s *\n", inputs[i]->name);

		if (!inputs[i]->modes) {
			printf("No parameter for this input\n");
		} else {
			struct input_mode *m = inputs[i]->modes;
			if (!m) {
				printf("No parameter for this input\n");
			} else {
				while (m) {
					printf("Mode %s : %s\n", m->name, m->descr);
					struct input_param *p = m->params;
					if (!p) {
						printf("No parameter for this mode\n");
					} else {
						while (p) {
							printf("  %s : %s\n", p->name, p->descr);
							p = p->next;
						}
					}
					m = m->next;
				}
			}
		}

		printf("\n");
	}
}
