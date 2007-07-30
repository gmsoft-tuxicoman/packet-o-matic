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


#include "helper.h"

#include "timers.h"
#include "rules.h"

#define MAX_HELPER MAX_MATCH

struct helper_reg *helpers[MAX_HELPER];
struct helper_functions *hlp_funcs;
struct helper_frame *frame_head, *frame_tail;

int helper_init() {

	hlp_funcs = malloc(sizeof(struct helper_functions));
	hlp_funcs->alloc_timer = timer_alloc;
	hlp_funcs->cleanup_timer = timer_cleanup;
	hlp_funcs->queue_timer = timer_queue;
	hlp_funcs->dequeue_timer = timer_dequeue;
	hlp_funcs->queue_frame = helper_queue_frame;
	hlp_funcs->layer_info_snprintf = layer_info_snprintf;
	hlp_funcs->conntrack_create_entry = conntrack_create_entry;
	hlp_funcs->conntrack_get_entry = conntrack_get_entry;
	hlp_funcs->conntrack_add_priv = conntrack_add_helper_priv;
	hlp_funcs->conntrack_get_priv = conntrack_get_helper_priv;

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



	int (*register_my_helper) (struct helper_reg *, struct helper_functions *);

	void *handle = NULL;
	register_my_helper = lib_get_register_func("helper", helper_name, &handle);
	
	if (!register_my_helper) {
		return -1;
	}

	struct helper_reg *my_helper = malloc(sizeof(struct helper_reg));
	bzero(my_helper, sizeof(struct helper_reg));


	if (!(*register_my_helper) (my_helper, hlp_funcs)) {
		dprint("Error while loading helper %s. Could not register helper !\n", helper_name);
		free(my_helper);
		return -1;
	}

	helpers[id] = my_helper;
	helpers[id]->dl_handle = handle;

	dprint("Helper %s registered\n", helper_name);


	return id;


}

/**
 * Parameters :
 *  - f : the frame to be examined
 *  - start : the start of the current header in the frame
 *  - len : the len of the current header + it's payload
 *  - l : the current layer
 **/

int helper_need_help(struct frame *f, unsigned int start, unsigned int len, struct layer *l) {

	if (!helpers[l->type] || !helpers[l->type]->need_help)
		return 0;

	return helpers[l->type]->need_help(f, start, len, l);

}


int helper_unregister_all() {

	int i;

	for (i = 0; i < MAX_HELPER; i++) {
		if (helpers[i]) {
			if (dlclose(helpers[i]->dl_handle))
				dprint("Error while closing library of target %s\n", match_get_name(i));
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


/**
 * Parameters :
 *  - frame : the content of the frame that needs to be processed
 *  - len : length of the frame
 *  - first_layer : first_layer of the frame
 **/
int helper_queue_frame(struct frame *f) {

	struct helper_frame *hf = malloc(sizeof(struct helper_frame));
	bzero(hf, sizeof(struct helper_frame));
	hf->f = f; // We don't do a copy. The helper provide us a struct frame and the corresponding buffer that we'll free

	if (!frame_head)
		frame_head = hf;

	if (!frame_tail)
		frame_tail = hf;
	else {
		frame_tail->next = hf;
		frame_tail = hf;
	}
	
	return 1;

}


int helper_process_queue(struct rule_list *list) {

	if (!frame_head)
		return 0;

	while (frame_head) {
		do_rules(frame_head->f, list);
		free(frame_head->f->buff);
		free(frame_head->f);
		struct helper_frame *tmpf = frame_head;
		frame_head = frame_head->next;
		free(tmpf);
	}
	frame_tail = NULL;

	return 1;
}

