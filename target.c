
#include "target.h"

#define MAX_TARGET 16


struct target_reg *targets[MAX_TARGET];

int target_register(const char *target_name) {

	int i;

	
	for (i = 0; i < MAX_TARGET; i++) {
		if (targets[i] != NULL) {
			if (strcmp(targets[i]->target_name, target_name) == 0) {
				return i;
			}
		} else {
			void *handle;
			char name[255];
			strcpy(name, "./target_");
			strcat(name, target_name);
			strcat(name, ".so");

			handle = dlopen(name, RTLD_NOW);

			if (!handle) {
				dprint("unable to load target %s : ", target_name);
				dprint(dlerror());
				dprint("\n");
				return -1;
			}
			dlerror();

			strcpy(name, "target_register_");
			strcat(name, target_name);

			int (*register_my_target) (struct target_reg *);

			
			register_my_target = dlsym(handle, name);
			if (!register_my_target) {
				dprint("error when finding symbol %s. could not load target !\n", target_name);
				return -1;
			}

			struct target_reg *my_target = malloc(sizeof(struct target_reg));
			bzero(my_target, sizeof(struct target_reg));

			
			if (!(*register_my_target) (my_target)) {
				dprint("error while loading target %s. could not load target !\n", target_name);
				return -1;
			}


			targets[i] = malloc(sizeof(struct target_reg));
			memcpy(targets[i], my_target, sizeof(struct target_reg));
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
		dprint("Input type %u is not registered\n", target_type);
		return NULL;
	}
	struct target *t = malloc(sizeof(struct target));
	t->target_type = target_type;
	t->match_register = match_register;
	
	if (targets[target_type]->init)
		if (!(*targets[target_type]->init) (t)) {
			free(t);
			return NULL;
		}
		
	return t;
}


int target_open(struct target *t, const char *params) {

	if (!t)
		return 0;

	if (targets[t->target_type] && targets[t->target_type]->open)
		return (*targets[t->target_type]->open) (t, params);
	return 1;

}

int target_process(struct target *t, struct rule_node *node, unsigned char *buffer, unsigned int bufflen) {

	if (targets[t->target_type]->process)
		return (*targets[t->target_type]->process) (t, node,  buffer, bufflen);
	return 1;

}

int target_close(struct target *t) {

	if (!t)
		return 1;

	if (targets[t->target_type] && targets[t->target_type]->close)
		return (*targets[t->target_type]->close) (t);
	return 1;

}

int target_cleanup(struct target *t) {

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
		free(targets[i]->target_name);
		dlclose(targets[i]->dl_handle);
		targets[i] = NULL;

	}

	return 1;

}

