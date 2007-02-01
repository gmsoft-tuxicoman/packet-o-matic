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


#include "helper.h"

#include "timers.h"
#include "rules.h"

#define MAX_HELPER MAX_MATCH

struct helper_reg *helpers[MAX_HELPER];
struct helper_functions *hlp_funcs;
struct rule_list *hlp_rules = NULL;

int helper_init() {

	hlp_funcs = malloc(sizeof(struct helper_functions));
	hlp_funcs->alloc_timer = timer_alloc;
	hlp_funcs->cleanup_timer = timer_cleanup;
	hlp_funcs->queue_timer = timer_queue;
	hlp_funcs->dequeue_timer = timer_dequeue;
	hlp_funcs->process_packet = helper_process_packet;

	dprint("Helper initialized\n");

	return 1;

}

int helper_register(const char *helper_name) {


	int id;
	id = match_get_type(helper_name);
	if (id == -1) {
		dprint("Unable to register helper %s. Corresponding match not found\n", helper_name);
		return -1;
	}

	if (helpers[id])
		return id;


	void *handle;
	char name[NAME_MAX];
	strcpy(name, "helper_");
	strcat(name, helper_name);
	strcat(name, ".so");

	handle = dlopen(name, RTLD_NOW);

	if (!handle) {
		dprint("Unable to load helper %s : ", helper_name);
		dprint(dlerror());
		dprint("\n");
		return -1;
	}
	dlerror();

	strcpy(name, "helper_register_");
	strcat(name, helper_name);

	int (*register_my_helper) (struct helper_reg *, struct helper_functions *);

	
	register_my_helper = dlsym(handle, name);
	if (!register_my_helper) {
		dprint("Error when finding symbol %s. Could not load helper !\n", helper_name);
		return -1;
	}

	struct helper_reg *my_helper = malloc(sizeof(struct helper_reg));
	bzero(my_helper, sizeof(struct helper_reg));


	if (!(*register_my_helper) (my_helper, hlp_funcs)) {
		dprint("Error while loading helper %s. Could not load helper !\n", helper_name);
		free(my_helper);
		return -1;
	}

	helpers[id] = my_helper;
	helpers[id]->dl_handle = handle;

	dprint("Helper %s registered\n", helper_name);


	return id;


}

int helper_need_help(void *frame, struct layer *l) {

	if (!helpers[l->type] || !helpers[l->type]->need_help)
		return 0;

	return helpers[l->type]->need_help(frame, l);

}


int helper_unregister_all() {

	int i;

	for (i = 0; i < MAX_HELPER; i++) {
		if (helpers[i]) {
			dlclose(helpers[i]->dl_handle);
			free(helpers[i]);
			helpers[i] = NULL;
		}

	}

	return 1;

}


int helper_cleanup() {

	int i;
	
	// Cleanup remaining helper's memory

	for (i = 0; i < MAX_HELPER; i++) {
		if (helpers[i] && helpers[i]->cleanup)
			(*helpers[i]->cleanup) ();
	}

	free(hlp_funcs);

	return 1;
}

int helper_set_feedback_rules(struct rule_list *rules) {

	hlp_rules = rules;
	return 1;

}

int helper_process_packet(void *frame, unsigned int len, int first_layer) {

	if (!hlp_rules) {
		dprint("Unable to process packet. Feedback rules not set !\n");
		return 0;
	}

	return do_rules(frame, 0, len, hlp_rules, first_layer);

}

