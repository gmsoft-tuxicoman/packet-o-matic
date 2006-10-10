

#include "input.h"

#undef MAX_INPUT
#define MAX_INPUT 16


struct input_reg *inputs[MAX_INPUT];

int input_register(const char *input_name) {


	int i;


	for (i = 0; i < MAX_INPUT; i++) {
		if (inputs[i] != NULL) {
			if (strcmp(inputs[i]->input_name, input_name) == 0) {
				return i;
			}
		} else {
			void *handle;
			char name[255];
			strcpy(name, "./input_");
			strcat(name, input_name);
			strcat(name, ".so");

			handle = dlopen(name, RTLD_NOW);

			if (!handle) {
				dprint("Unable to load input %s : ", input_name);
				dprint(dlerror());
				dprint("\n");
				return -1;
			}
			dlerror();

			strcpy(name, "input_register_");
			strcat(name, input_name);

			int (*register_my_input) (struct input_reg *);

			
			register_my_input = dlsym(handle, name);
			if (!register_my_input) {
				dprint("Error when finding symbol %s. Could not load input !\n", input_name);
				return -1;
			}

			struct input_reg *my_input = malloc(sizeof(struct input_reg));
			bzero(my_input, sizeof(struct input_reg));

			
			if (!(*register_my_input) (my_input)) {
				dprint("Error while loading input %s. Could not load input !\n", input_name);
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
		int j;
		for (j = 0; inputs[i]->params_name[j]; j++) {
			free(inputs[i]->params_name[j]);
			free(inputs[i]->params_help[j]);
		}
		free(inputs[i]->params_name);
		free(inputs[i]->params_help);
		free(inputs[i]->input_name);
		dlclose(inputs[i]->dl_handle);
		free(inputs[i]);
		inputs[i] = NULL;

	}

	return 1;

}
