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


#include "target.h"
#include "conntrack.h"
#include "ptype.h"

#define MAX_TARGET 16


struct target_reg *targets[MAX_TARGET];
struct target_functions tg_funcs;

int target_init() {

	tg_funcs.pom_log = pom_log;
	tg_funcs.match_register = match_register;
	tg_funcs.register_mode = target_register_mode;
	tg_funcs.register_param = target_register_param;
	tg_funcs.register_param_value = target_register_param_value;
	tg_funcs.ptype_alloc = ptype_alloc;
	tg_funcs.ptype_cleanup = ptype_cleanup_module;
	tg_funcs.conntrack_create_entry = conntrack_create_entry;
	tg_funcs.conntrack_add_priv = conntrack_add_target_priv;
	tg_funcs.conntrack_get_priv = conntrack_get_target_priv;
	tg_funcs.layer_info_snprintf = layer_info_snprintf;
	tg_funcs.match_get_name = match_get_name;

	pom_log(POM_LOG_DEBUG "Targets initialized\r\n");

	return POM_OK;

}

int target_register(const char *target_name) {

	int i;

	
	for (i = 0; i < MAX_TARGET; i++) {
		if (targets[i] != NULL) {
			if (strcmp(targets[i]->target_name, target_name) == 0) {
				return i;
			}
		} else {
			int (*register_my_target) (struct target_reg *, struct target_functions *);

			void *handle = NULL;
			register_my_target = lib_get_register_func("target", target_name, &handle);

			if (!register_my_target) {
				return POM_ERR;
			}

			struct target_reg *my_target = malloc(sizeof(struct target_reg));
			bzero(my_target, sizeof(struct target_reg));

			targets[i] = my_target;
			my_target->type = i;

			if ((*register_my_target) (my_target, &tg_funcs) != POM_OK) {
				pom_log(POM_LOG_ERR "Error while loading target %s. could not register target !\r\n", target_name);
				targets[i] = NULL;
				free(my_target);
				return POM_ERR;
			}


			targets[i]->target_name = malloc(strlen(target_name) + 1);
			strcpy(targets[i]->target_name, target_name);
			targets[i]->dl_handle = handle;

			pom_log(POM_LOG_DEBUG "Target %s registered\r\n", target_name);
			
			return i;
		}
	}


	return POM_ERR;

}

struct target_mode *target_register_mode(int target_type, const char *name, const char *descr) {

	if (!targets[target_type])
		return NULL;

	struct target_mode *mode = malloc(sizeof(struct target_mode));
	bzero(mode, sizeof(struct target_mode));
	
	mode->name = malloc(strlen(name) + 1);
	strcpy(mode->name, name);
	mode->descr = malloc(strlen(descr) + 1);
	strcpy(mode->descr, descr);
	
	if (!targets[target_type]->modes) {
		targets[target_type]->modes = mode;
	} else {
		struct target_mode *tmpm = targets[target_type]->modes;
		while (tmpm->next)
			tmpm = tmpm->next;
		tmpm->next = mode;
	}

	return mode;

}

int target_register_param(struct target_mode *mode, char *name, char *defval, char *descr) {

	if (!mode)
		return POM_ERR;

	struct target_param_reg *param = malloc(sizeof(struct target_param_reg));
	bzero(param, sizeof(struct target_param_reg));

	param->name = malloc(strlen(name) + 1);
	strcpy(param->name, name);
	param->defval = malloc(strlen(name) + 1);
	strcpy(param->defval, defval);
	param->descr = malloc(strlen(descr) + 1);
	strcpy(param->descr, descr);

	if (!mode->params) {
		mode->params = param;
	} else {
		struct target_param_reg *tmp = mode->params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = param;
	}

	return POM_OK;
}

int target_register_param_value(struct target *t, struct target_mode *mode, const char *name, struct ptype *value) {

	if (!t || !mode || !value)
		return POM_ERR;

	struct target_param_reg *p = mode->params;
	while (p) {
		if (!strcmp(p->name, name))
			break;
		p = p->next;
	}
	if (!p)
		return POM_ERR;

	if (ptype_parse_val(value, p->defval) != POM_OK)
		return POM_ERR;

	struct target_param *tp = malloc(sizeof(struct target_param));
	bzero(tp, sizeof(struct target_param));

	tp->type = p;
	tp->value = value;


	struct target_param *tmp = t->params;

	if (!tmp) {
		t->params = tp;
	} else {
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = tp;

	}

	return POM_OK;


}

struct target *target_alloc(int target_type) {

	if (!targets[target_type]) {
		pom_log(POM_LOG_ERR "Target type %u is not registered\r\n", target_type);
		return NULL;
	}
	struct target *t = malloc(sizeof(struct target));
	bzero(t, sizeof(struct target));

	t->type = target_type;
	
	if (targets[target_type]->init)
		if ((*targets[target_type]->init) (t) != POM_OK) {
			free(t);
			return NULL;
		}

	// Default mode is the first one
	t->mode = targets[target_type]->modes;
		
	return t;
}

int target_set_mode(struct target *t, const char *mode_name) {

	if (!t)
		return POM_ERR;
	
	struct target_mode *mode = targets[t->type]->modes;
	while (mode) {
		if (!strcmp(mode->name, mode_name)) {
			t->mode = mode;
			return POM_OK;
		}
		mode = mode->next;
	}

	return POM_ERR;
}

struct ptype *target_get_param_value(struct target *t, const char *param) {

	if (!t)
		return NULL;

	if (!t->mode)
		return NULL;

	struct target_param_reg *pr = t->mode->params;
	while (pr) {
		if (!strcmp(pr->name, param))
			break;
		pr = pr->next;
	}

	if (!pr)
		return NULL;

	struct target_param *p = t->params;
	while (p) {
		if (p->type == pr)
			break;

		p = p->next;
	}
	
	if (!p)
		return NULL;

	return p->value;

}

char *target_get_name(int target_type) {

	if (!targets[target_type])
		return NULL;

	return targets[target_type]->target_name;

}

int target_open(struct target *t) {

	if (!t)
		return POM_ERR;

	if (targets[t->type] && targets[t->type]->open)
		return (*targets[t->type]->open) (t);
	return POM_OK;

}

int target_process(struct target *t, struct frame *f) {

	if (targets[t->type]->process)
		return (*targets[t->type]->process) (t, f);
	return POM_OK;

}

int target_close(struct target *t) {

	if (!t)
		return POM_ERR;

	if (targets[t->type] && targets[t->type]->close)
		return (*targets[t->type]->close) (t);
	return POM_OK;

}

int target_cleanup_module(struct target *t) {

	if (!t)
		return POM_ERR;

	if (targets[t->type]) {
		if (targets[t->type]->cleanup)
			(*targets[t->type]->cleanup) (t);
		struct target_param *p = t->params;
		while (p) {
			p = p->next;
			free(t->params);
			t->params = p;
		}
	}
	
	free (t);

	return POM_OK;

}

int target_unregister(int target_type) {

	if (!targets[target_type])
		return POM_ERR;

	struct target_mode *mode = targets[target_type]->modes;

	while (mode) {
		
		struct target_param_reg *p = mode->params;
		while (p) {
			free(p->name);
			free(p->defval);
			free(p->descr);
			p = p->next;
			free(mode->params);
			mode->params = p;
		}

		free(mode->name);
		free(mode->descr);
		mode = mode->next;
		free(targets[target_type]->modes);
		targets[target_type]->modes = mode;
	}

	if(dlclose(targets[target_type]->dl_handle))
		pom_log(POM_LOG_WARN "Error while closing library of target %s\r\n", targets[target_type]->target_name);
	free(targets[target_type]->target_name);
	free(targets[target_type]);
	targets[target_type] = NULL;

	return POM_OK;

}

int target_unregister_all() {

	int i = 0;

	for (; i < MAX_TARGET && targets[i]; i++) {
		target_unregister(i);
	}

	return POM_OK;

}

int target_cleanup() {

	return POM_OK;

}


void target_print_help() {

	int i;


	for (i = 0; targets[i]; i++) {
		printf("* TARGET %s *\n", targets[i]->target_name);

		if (!targets[i]->modes) {
			printf("No parameter for this target\n");
		} else {
			struct target_mode *m = targets[i]->modes;
			while (m) {
				printf("Mode %s : %s\n", m->name, m->descr);
				struct target_param_reg *p = m->params;
				if (!p) {
					printf("  No parameter for this mode\n");
				} else {
					while (p) {
						printf("  %s : %s\n", p->name, p->descr);
						p = p->next;
					}
				}
				m = m->next;
			}


		}
		printf("\n");
	}
}
