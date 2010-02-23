/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2010 Guy Martin <gmsoft@tuxicoman.be>
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

/**
 * @defgroup input_api Input API
 */


#include "common.h"
#include "input.h"
#include "match.h"
#include "timers.h"
#include "ptype.h"
#include "ptype_uint64.h"
#include "ptype_bool.h"
#include "perf.h"
#include "core_param.h"

struct input_reg *inputs[MAX_INPUT];

static pthread_rwlock_t input_global_lock = PTHREAD_RWLOCK_INITIALIZER;

static struct perf_class *input_perf_class = NULL;

/**
 * @ingroup input_api
 * @param input_name Name of the input
 * @return Input type on success or POM_ERR on failure.
 * This function will try to find the module input_<name>.so and
 * call the function input_<name>_register() from it.
 **/
int input_register(const char *input_name) {


	int i;


	for (i = 0; i < MAX_INPUT; i++) {
		if (inputs[i] != NULL) {
			if (strcmp(inputs[i]->name, input_name) == 0) {
				return i;
			}
		} else {

			int (*register_my_input) (struct input_reg *);

			void *handle = NULL;
			register_my_input = lib_get_register_func("input", input_name, &handle);


			if (!register_my_input) {
				return POM_ERR;
			}

			struct input_reg *my_input = malloc(sizeof(struct input_reg));
			memset(my_input, 0, sizeof(struct input_reg));
			my_input->type = i;
			inputs[i] = my_input;
			inputs[i]->dl_handle = handle;

			match_lock(1); // Allow safe registration of the matches
			if ((*register_my_input) (my_input) != POM_OK) {
				match_unlock();
				pom_log(POM_LOG_ERR "Error while loading input %s. Could not register input !", input_name);
				inputs[i] = NULL;
				free(my_input);
				return POM_ERR;
			}
			match_unlock();

			inputs[i] = my_input;
			inputs[i]->name = malloc(strlen(input_name) + 1);
			strcpy(inputs[i]->name, input_name);
			inputs[i]->dl_handle = handle;

			pom_log(POM_LOG_DEBUG "Input %s registered", input_name);


			return i;

		}

	}

	input_perf_class = perf_register_class("input");

	return POM_ERR;

}

/**
 * @ingroup input_api
 * The first registered mode will be the default mode.
 * @param input_type Type of the input
 * @param name Name of the mode to register
 * @param descr Description of the mode
 * @return Pointer to the allocated mode. On failure returns NULL.
 **/
struct input_mode *input_register_mode(int input_type, const char *name, const char *descr) {

	if (!inputs[input_type])
		return NULL;
	
	struct input_mode *mode = malloc(sizeof(struct input_mode));
	memset(mode, 0, sizeof(struct input_mode));
	
	mode->name = malloc(strlen(name) + 1);
	strcpy(mode->name, name);
	mode->descr = malloc(strlen(descr) + 1);
	strcpy(mode->descr, descr);
	
	if (!inputs[input_type]->modes) {
		inputs[input_type]->modes = mode;
	} else {
		struct input_mode *tmpm = inputs[input_type]->modes;
		while (tmpm->next)
			tmpm = tmpm->next;
		tmpm->next = mode;
	}

	return mode;

}

/**
 * @ingroup input_api
 * @param i Input to set mode to
 * @param mode_name Name of the mode
 * @return POM_OK on success, POM_ERR on error.
 **/
int input_set_mode(struct input *i, char *mode_name) {
	if (!i)
		return POM_ERR;
	if (i->running)
		return POM_ERR;
	struct input_mode *mode = inputs[i->type]->modes;
	while (mode) {
		if (!strcmp(mode->name, mode_name)) {
			i->mode = mode;
			return POM_OK;
		}
		mode = mode->next;
	}

	return POM_ERR;

 }

/**
 * @ingroup input_api
 * @param mode Mode to add a parameter to
 * @param name Name of the parameter
 * @param defval Default value of the parameter
 * @param value Ptype used to store the actual value of the parameter
 * @param descr Description of the parameter
 * @return POM_OK on sucess, POM_ERR on error.
 **/
int input_register_param(struct input_mode *mode, char *name, char *defval, struct ptype *value, char *descr) {

	if (!mode)
		return POM_ERR;

	struct input_param *param = malloc(sizeof(struct input_param));
	memset(param, 0, sizeof(struct input_param));

	param->name = malloc(strlen(name) + 1);
	strcpy(param->name, name);
	param->defval = malloc(strlen(defval) + 1);
	strcpy(param->defval, defval);
	param->descr = malloc(strlen(descr) + 1);
	strcpy(param->descr, descr);
	param->value = value;

	if (ptype_parse_val(param->value, defval) == POM_ERR)
		return POM_ERR;

	if (!mode->params) {
		mode->params = param;
	} else {
		struct input_param *tmp = mode->params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = param;
	}

	return POM_OK;
}

/**
 * @ingroup input_api
 * @param input_type Type of the input
 * @return Pointer to the input name.
 **/
char *input_get_name(int input_type) {
	if (!inputs[input_type])
		return NULL;
	
	return inputs[input_type]->name;
}

/**
 * @ingroup input_api
 * @param input_name Name of the input to get the type
 * @return The type of the input.
 **/
int input_get_type(char* input_name) {

	int i;
	for (i = 0; i < MAX_INPUT; i++) {
		if (inputs[i] && strcmp(inputs[i]->name, input_name) == 0)
			return i;
	}
	
	return POM_ERR;
}

/**
 * @ingroup input_core
 * @param input_type Type of the input
 * @return A pointer to the allocated struct input on success or POM_ERR on failure.
 **/
struct input *input_alloc(int input_type) {

	if (!inputs[input_type]) {
		pom_log(POM_LOG_ERR "Input type %u is not registered", input_type);
		return NULL;
	}

	if (!input_perf_class)
		input_perf_class = perf_register_class("input");

	struct input *i = malloc(sizeof(struct input));
	memset(i, 0, sizeof(struct input));

	i->type = input_type;
	i->perfs = perf_register_instance(input_perf_class, i);
	
	if (inputs[input_type]->init)
		if ((*inputs[input_type]->init) (i) != POM_OK) {
			perf_unregister_instance(input_perf_class, i->perfs);
			free(i);
			return NULL;
		}

	inputs[input_type]->refcount++;

	i->perf_pkts_in = perf_add_item(i->perfs, "pkts_in", perf_item_type_counter, "Number of packets read");
	i->perf_bytes_in = perf_add_item(i->perfs, "bytes_in", perf_item_type_counter, "Number of bytes read");
	i->perf_uptime = perf_add_item(i->perfs, "uptime", perf_item_type_uptime, "Runtime");
	
	// assign default mode
	i->mode = inputs[input_type]->modes;
	    
	return i;
}

/**
 * @ingroup input_core
 * @param i Pointer to an allocated struct input
 * @return POM_OK or POM_ERR on failure.
 **/
int input_open(struct input *i) {

	if (!i)
		return POM_ERR;

	if (i->running)
		return POM_ERR;

	int res = POM_ERR;
	if (inputs[i->type] && inputs[i->type]->open) {
		res = (*inputs[i->type]->open) (i);
		if (res == POM_ERR)
			return POM_ERR;
	}


	struct ptype* param_reset_counters_on_restart = core_get_param_value("reset_counters_on_item_restart");
	if (PTYPE_BOOL_GETVAL(param_reset_counters_on_restart)) {
		perf_instance_items_val_reset(i->perfs);
	} else {
		perf_item_val_uptime_restart(i->perf_uptime);
	}

	i->running = 1;
	return res;
}

/**
 * @ingroup input_core
 * @param i Pointer to the input to read from
 * @param f Pointer to a struct frame where to store the packet read
 * @return The number of bytes copied, 0 if nothing was read and POM_ERR in case of fatal error.
 * The buffer used in the struct frame should be at least the size of the snaplen returned by input_get_caps. The argument bufflen is the length of the buffer.
 **/
int input_read(struct input *i, struct frame *f) {

	if (!i->running)
		return POM_ERR;
	
	int res = (*inputs[i->type]->read) (i, f);
	if (res == POM_ERR) {
		input_close(i);
		return POM_ERR;
	}

	if (f->len > 0) { // frames with 0 length must be ignored
		perf_item_val_inc(i->perf_pkts_in, 1);
		perf_item_val_inc(i->perf_bytes_in, f->len);
	}
	return res;
}

/**
 * @ingroup input_core
 * @param i Pointer to an struct input
 * @return POM_OK on success, POM_ERR on failure.
 **/
int input_close(struct input *i) {

	if (!i)
		return POM_ERR;
	
	if (!i->running)
		return POM_ERR;

	perf_item_val_uptime_stop(i->perf_uptime);

	i->running = 0;

	if (inputs[i->type] && inputs[i->type]->close) 
		return (*inputs[i->type]->close) (i);

	return POM_ERR;

}

/**
 * @ingroup input_core
 * @param i Pointer to the struct input to free
 * @returns POM_OK on success, POM_ERR on failure.
 **/
int input_cleanup(struct input *i) {

	if (!i)
		return POM_ERR;

	if (inputs[i->type] && inputs[i->type]->cleanup)
		(*inputs[i->type]->cleanup) (i);

	inputs[i->type]->refcount--;

	perf_unregister_instance(input_perf_class, i->perfs);

	free (i);
	
	return POM_ERR;

}

/**
 * @ingroup input_core
 * @param input_type Type of the input to unregister
 * @return POM_OK on success, POM_ERR on failure.
 **/
int input_unregister(int input_type) {
	
	if (!inputs[input_type])
		return POM_ERR;

	if (inputs[input_type]->refcount) {
		pom_log(POM_LOG_ERR "Cannot unload input %s. Reference count > 0", inputs[input_type]->name);
		return POM_ERR;
	}

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
		pom_log(POM_LOG_WARN "Error while closing library of input %s", inputs[input_type]->name);
	pom_log(POM_LOG_DEBUG "Input %s unregistered", inputs[input_type]->name);
	free(inputs[input_type]->name);
	free(inputs[input_type]);
	inputs[input_type] = NULL;
	return POM_OK;
}

/**
 * @ingroup input_core
 * @return POM_OK on success, POM_ERR on failure.
 **/
int input_unregister_all() {

	int i;
	int result = POM_OK;

	for (i = 0; i < MAX_INPUT; i++) 
		if (inputs[i] && input_unregister(i) == POM_ERR)
			result = POM_ERR;
	return result;

}

/**
 * @ingroup input_core
 * @param i Pointer to a opened input
 * @param ic Pointer to an allocated struct input_caps
 * @return POM_OK on sucess, POM_ERR on failure.
 */

int input_getcaps(struct input *i, struct input_caps *ic) {

	if (!i || !inputs[i->type])
		return POM_ERR;

	return (*inputs[i->type]->getcaps) (i, ic);
	

}

/**
 * @ingroup input_core
 */
void input_print_help() {

	int i;


	for (i = 0; i < MAX_INPUT; i++) {
		if (!inputs[i])
			continue;

		printf("* INPUT %s *\n", inputs[i]->name);

		if (!inputs[i]->modes) {
			printf("No parameter for this input\n");
		} else {
			struct input_mode *m = inputs[i]->modes;
			while (m) {
				printf("Mode %s : %s\n", m->name, m->descr);
				struct input_param *p = m->params;
				if (!p) {
					printf("  No parameter for this mode\n");
				} else {
					while (p) {
						printf("  %s : %s (Default : %s", p->name, p->descr, p->defval);
						if (strlen(p->value->unit) > 0)
							printf(" %s", p->value->unit);
						printf(")\n");
						p = p->next;
					}
				}
				m = m->next;
			}
		}

		printf("\n");
	}
}

/**
 * @ingroup input_core
 * @param i Input to interrupt
 * @return POM_OK on success, POM_ERR on failure
 */

int input_interrupt(struct input *i) {

	if (!i)
		return POM_ERR;

	if (inputs[i->type]->interrupt)
		return (*inputs[i->type]->interrupt) (i);

	return POM_OK;
}

/**
 * @ingroup input_core
 * This lock will be used each time an input is registered or
 * unregistered. Also used when looking informations about inputs
 * which may not have a positive refcount.
 * @param write Set to 1 if helpers will be modified, 0 if not
 * @return POM_OK on success, POM_ERR on failure.
 */
int input_lock(int write) {

	int result = 0;
	if (write) {
		result = pthread_rwlock_wrlock(&input_global_lock);
	} else {
		result = pthread_rwlock_rdlock(&input_global_lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking the input lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

/**
 * @ingroup input_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int input_unlock() {

	if (pthread_rwlock_unlock(&input_global_lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the input lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

