/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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
#include "ptype.h"
#include "rules.h"

struct helper_frame *frame_head, *frame_tail;

/**
 * @ingroup helper_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int helper_init() {

	frame_head = NULL;
	frame_tail = NULL;

	pom_log(POM_LOG_DEBUG "Helper initialized\r\n");

	return POM_OK;

}

/**
 * @ingroup helper_core
 * @param helper_name Name of the helper
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int helper_register(const char *helper_name) {


	int id;
	id = match_get_type(helper_name);
	if (id == -1) {
		pom_log(POM_LOG_WARN "Unable to register helper %s. Corresponding match not found\r\n", helper_name);
		return POM_ERR;
	}

	if (helpers[id])
		return id;



	int (*register_my_helper) (struct helper_reg *);

	void *handle = NULL;
	register_my_helper = lib_get_register_func("helper", helper_name, &handle);
	
	if (!register_my_helper) {
		return POM_ERR;
	}

	struct helper_reg *my_helper = malloc(sizeof(struct helper_reg));
	memset(my_helper, 0, sizeof(struct helper_reg));
	my_helper->type = id;
	helpers[id] = my_helper;
	helpers[id]->dl_handle = handle;

	if ((*register_my_helper) (my_helper) != POM_OK) {
		pom_log(POM_LOG_ERR "Error while loading helper %s. Could not register helper !\r\n", helper_name);
		helpers[id] = NULL;
		free(my_helper);
		return POM_ERR;
	}


	pom_log(POM_LOG_DEBUG "Helper %s registered\r\n", helper_name);


	return id;


}

/**
 * @ingroup helper_api
 * @param helper_type Type of helper to register the parameter to
 * @param name Name of the parameter to register
 * @param defval Default value of the parameter
 * @param value Actual value of the parmeter
 * @param descr Description of the parameter
 * @return POM_OK on success, POM_ERR on error.
 */
int helper_register_param(int helper_type, char *name, char *defval, struct ptype *value, char *descr) {

	if (!helpers[helper_type])
		return POM_ERR;

	// Store the default value in the ptype
	if (ptype_parse_val(value, defval) == POM_ERR)
		return POM_ERR;

	struct helper_param *p = malloc(sizeof(struct helper_param));
	memset(p, 0, sizeof(struct helper_param));
	p->name = malloc(strlen(name) + 1);
	strcpy(p->name, name);
	p->defval = malloc(strlen(defval) + 1);
	strcpy(p->defval, defval);
	p->descr = malloc(strlen(descr) + 1);
	strcpy(p->descr, descr);
	p->value = value;

	if (!helpers[helper_type]->params) {
		helpers[helper_type]->params = p;
	} else {
		struct helper_param *tmp = helpers[helper_type]->params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = p;
	}

	return POM_OK;


}

/**
 * @ingroup helper_core
 * @param helper_type Type of the helper
 * @param param_name Name of the parameter
 * @return The matched parameter or NULL if not found.
 */
struct helper_param* helper_get_param(int helper_type, char* param_name) {

	if (!helpers[helper_type])
		return NULL;

	struct helper_param *p = helpers[helper_type]->params;

	while (p) {
		if (!strcmp(p->name, param_name))
			return p;
		p = p->next;
	}

	return NULL;
}

/**
 * @ingroup helper_core
 * @param f The frame to be examined
 * @param start The start of the current header in the frame
 * @param len The len of the current header + it's payload
 * @param l The current layer
 * @return POM_OK on sucess, H_NEED_HELP if packet should not be processed anymore or POM_ERR on failure.
 */
int helper_need_help(struct frame *f, unsigned int start, unsigned int len, struct layer *l) {

	if (!helpers[l->type] || !helpers[l->type]->need_help)
		return POM_OK;

	return helpers[l->type]->need_help(f, start, len, l);

}

/**
 * @ingroup helper_core
 * @param helper_type Helper to unregister
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int helper_unregister(int helper_type) {

	if (helpers[helper_type]) {
		if (helpers[helper_type]->cleanup)
			(*helpers[helper_type]->cleanup) ();
		void *handle = helpers[helper_type]->dl_handle;
		while (helpers[helper_type]->params) {
			free(helpers[helper_type]->params->name);
			free(helpers[helper_type]->params->defval);
			free(helpers[helper_type]->params->descr);
			struct helper_param *next = helpers[helper_type]->params->next;
			free(helpers[helper_type]->params);
			helpers[helper_type]->params = next;

		}
		free(helpers[helper_type]);
		helpers[helper_type] = NULL;
		if (dlclose(handle))
			pom_log(POM_LOG_WARN "Error while closing library of target %s\r\n", match_get_name(helper_type));

		pom_log(POM_LOG_DEBUG "Helper %s unregistered\r\n", match_get_name(helper_type));
	} 

	return POM_OK;

}

/**
 * @ingroup helper_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int helper_unregister_all() {

	int i;
	int result = POM_OK;

	for (i = 0; i < MAX_HELPER; i++) {
		if (helpers[i] && helper_unregister(i) == POM_ERR)
			result = POM_ERR;
	}

	return result;

}

/**
 * @ingroup helper_core
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int helper_cleanup() {

	return POM_OK;
}


/**
 * @ingroup helper_api
 * @param f The content of the frame that needs to be processed
 * @return POM_OK on success, POM_ERR on failure.
 **/
int helper_queue_frame(struct frame *f) {

	struct helper_frame *hf = malloc(sizeof(struct helper_frame));
	memset(hf, 0, sizeof(struct helper_frame));
	hf->f = f; // We don't do a copy. The helper provide us a struct frame and the corresponding buffer that we'll free

	if (!frame_head)
		frame_head = hf;

	if (!frame_tail)
		frame_tail = hf;
	else {
		frame_tail->next = hf;
		frame_tail = hf;
	}
	
	return POM_OK;

}

/**
 * @ingroup helper_core
 * @param list Rule list to use when processing queued packets
 * @return POM_OK on success, POM_ERR on failure
 */
int helper_process_queue(struct rule_list *list) {

	if (!frame_head)
		return POM_OK;

	while (frame_head) {
		do_rules(frame_head->f, list);
		free(frame_head->f->buff_base);
		free(frame_head->f);
		struct helper_frame *tmpf = frame_head;
		frame_head = frame_head->next;
		free(tmpf);
	}
	frame_tail = NULL;

	return POM_OK;
}

