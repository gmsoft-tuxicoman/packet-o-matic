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
#include "match.h"
#include "ptype.h"
#include "conntrack.h"

struct match_reg *matchs[MAX_MATCH];
static struct match_functions *m_funcs;

int match_undefined_id;


int match_register(const char *match_name) {

	int i;

	for (i = 0; i < MAX_MATCH; i++) {
		if (matchs[i] != NULL) {
			if (matchs[i]->name && strcmp(matchs[i]->name, match_name) == 0) {
				return i;
			}
		} else {
			int (*register_my_match) (struct match_reg *, struct match_functions *);

			void *handle = NULL;
			register_my_match = lib_get_register_func("match", match_name, &handle);
			
			if (!register_my_match) {
				return POM_ERR;
			}

			struct match_reg *my_match = malloc(sizeof(struct match_reg));
			bzero(my_match, sizeof(struct match_reg));

			
			matchs[i] = my_match;
			matchs[i]->name = malloc(strlen(match_name) + 1);
			strcpy(matchs[i]->name, match_name);

			my_match->type = i; // Allow the match to know it's number at registration time

			if ((*register_my_match) (my_match, m_funcs) != POM_OK) {
				pom_log(POM_LOG_ERR "Error while loading match %s. Could not register match !\r\n", match_name);
				free(my_match->name);
				free(my_match);
				matchs[i] = NULL;
				return POM_ERR;
			}

			matchs[i]->dl_handle = handle;

			pom_log(POM_LOG_DEBUG "Match %s registered\r\n", match_name);

			// Automatically load the conntrack
			conntrack_register(match_name);


			return i;

		}

	}

	return POM_ERR;

}

struct match_field_reg* match_register_field(int match_type, char *name, struct ptype *type, char *descr) {

	if (!matchs[match_type])
		return NULL;

	struct match_field_reg *p = malloc(sizeof(struct match_field_reg));
	bzero(p, sizeof(struct match_field_reg));

	p->name = malloc(strlen(name) + 1);
	strcpy(p->name, name);
	p->descr = malloc(strlen(descr) + 1);
	strcpy(p->descr, descr);

	if (!matchs[match_type]->fields)
		matchs[match_type]->fields = p;
	else {
		struct match_field_reg *tmp = matchs[match_type]->fields;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = p;
	}

	p->type = type;

	return p;

}

struct match_field *match_alloc_field(int match_type, char *field_type) {


	if (!matchs[match_type])
		return NULL;

	struct match_field_reg *p = matchs[match_type]->fields;
	while (p) {
		if (!strcmp(p->name, field_type))
			break;
		p = p->next;
	}

	if (!p)
		return NULL;
	
	struct match_field *ret;
	ret = malloc(sizeof(struct match_field));
	bzero(ret, sizeof(struct match_field));


	ret->value = ptype_alloc_from(p->type);
	if (!ret->value) {
		free(ret);
		return NULL;
	}

	ret->field = p;
	return ret;
}

int match_cleanup_field(struct match_field *p) {

	ptype_cleanup_module(p->value);
	free(p);

	return POM_OK;
}

int match_init() {

	match_undefined_id = match_register("undefined");

	m_funcs = malloc(sizeof(struct match_functions));
	m_funcs->pom_log = pom_log;
	m_funcs->match_register = match_register;
	m_funcs->register_field = match_register_field;
	m_funcs->ptype_alloc = ptype_alloc;
	m_funcs->ptype_cleanup = ptype_cleanup_module;

	return POM_OK;
}

char *match_get_name(int match_type) {

	if (matchs[match_type])
		return matchs[match_type]->name;
	
	return NULL;

}

struct match_field_reg *match_get_fields(int match_type) {

	return matchs[match_type]->fields;

}


int match_get_type(const char *match_name) {

	int i;
	for (i = 0; i < MAX_MATCH && matchs[i]; i++) {
		if (strcmp(matchs[i]->name, match_name) == 0)
			return i;
	}

	return POM_ERR;
}

/**
 * Identify the next layer of this frame.
 * Returns the next layer that has been identified.
 **/

int match_identify(struct frame *f, struct layer *l, unsigned int start, unsigned int len) {
	
	if (matchs[l->type]->identify)
		return (*matchs[l->type]->identify) (f, l, start, len);

	return match_undefined_id;

}

/**
 * Evaluate a parameter to match a packet.
 * This must be used after match_identify() identified the whole packet
 **/

int match_eval(struct match_field *mf, struct layer *l) {

	struct layer_field *lf = l->fields;
	while (lf) {
		if (mf->field == lf->type)
			break;
		lf = lf->next;
	}

	if (!lf)
		return 0;

	return ptype_compare_val(mf->op, mf->value, lf->value);
	
}


int match_cleanup() {

	if (m_funcs)
		free(m_funcs);
	m_funcs = NULL;

	return POM_OK;
}


int match_unregister(unsigned int match_type) {

	struct match_reg *r = matchs[match_type];

	if (!r)
		return POM_ERR;

	while (r->fields) {
		struct match_field_reg *tmp = r->fields;
		free(tmp->name);
		free(tmp->descr);
		r->fields = tmp->next;
		free(tmp);

	}

	if (r->unregister)
		(*r->unregister) (r);
	
	if (dlclose(r->dl_handle))
		pom_log(POM_LOG_WARN "Error while closing library of match %s\r\n", r->name);

	pom_log(POM_LOG_DEBUG "Match %s unregistered\r\n", r->name);

	free(r->name);
	free(r);

	matchs[match_type] = NULL;

	return POM_OK;
}

int match_unregister_all() {

	int i = 0;

	for (; i < MAX_MATCH && matchs[i]; i++)
		match_unregister(i);

	return POM_OK;

}

void match_print_help() {

	int i;


	for (i = 0; matchs[i]; i++) {
		printf("* MATCH %s *\n", matchs[i]->name);
		
		if (!matchs[i]->fields)
			printf("No field for this match\n");
		else {
			struct match_field_reg *p;
			p = matchs[i]->fields;
			while (p) {
				printf("  %s : %s\n", p->name, p->descr);
				p = p->next;
			}
		}
		printf("\n");
	}
}
