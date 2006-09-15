

#include "match.h"

#undef MAX_MATCH
#define MAX_MATCH 16


struct match_reg *matchs[MAX_MATCH];

int match_register(const char *match_name) {

	int i;

	for (i = 0; i < MAX_MATCH; i++) {
		if (matchs[i] != NULL) {
			if (strcmp(matchs[i]->match_name, match_name) == 0) {
				return i;
			}
		} else {
			void *handle;
			char name[255];
			strcpy(name, "./match_");
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
				return -1;
			}

			matchs[i] = malloc(sizeof(struct match_reg));
			memcpy(matchs[i], my_match, sizeof(struct match_reg));
			matchs[i]->match_name = malloc(strlen(match_name) + 1);
			strcpy(matchs[i]->match_name, match_name);
			matchs[i]->dl_handle = handle;

			dprint("Match %s registered\n", match_name);

			return i;

		}

	}

	return -1;

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


int match_config(struct match *m, void *params) {

	if (!m)
		return 0;

	if (matchs[m->match_type] && matchs[m->match_type]->config)
		return (*matchs[m->match_type]->config) (m, params);
	return 1;

}

inline int match_eval(struct match *m, void* frame, unsigned int start, unsigned int len) {
	
	return (*matchs[m->match_type]->eval) (m, frame, start, len);

}


int match_cleanup(struct match *m) {

	if (!m)
		return 0;

	if (!matchs[m->match_type] && matchs[m->match_type]->cleanup)
		(*matchs[m->match_type]->cleanup) (m);

	free(m);

	return 1;

}

int match_unregister_all() {

	int i = 0;

	for (; i < MAX_MATCH && matchs[i]; i++) {
		free(matchs[i]->match_name);
		dlclose(matchs[i]->dl_handle);
		matchs[i] = NULL;

	}

	return 1;

}

