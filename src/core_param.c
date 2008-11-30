/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2008 Guy Martin <gmsoft@tuxicoman.be>
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
#include "core_param.h"

static struct core_param *core_params;
static uint32_t core_params_serial;


int core_register_param(char *name, char *defval, struct ptype *value, char *descr, int (*callback) (char *new_value, char *msg, size_t size)) {

	struct core_param *p = malloc(sizeof(struct core_param));
	memset(p, 0, sizeof(struct core_param));

	p->name = malloc(strlen(name) + 1);
	strcpy(p->name, name);
	p->defval = malloc(strlen(defval) + 1);
	strcpy(p->defval, defval);
	p->descr = malloc(strlen(descr) + 1);
	strcpy(p->descr, descr);
	p->value = value;

	p->callback = callback;

	if (ptype_parse_val(p->value, defval) == POM_ERR)
		return POM_ERR;

	p->next = core_params;
	core_params = p;

	return POM_OK;

}

struct ptype* core_get_param_value(char *param) {

	struct core_param *p = core_params;
	while (p) {
		if (!strcmp(p->name, param))
			return p->value;
		p = p->next;
	}

	return NULL;

}

int core_set_param_value(char *param, char *value, char *msg, size_t size) {

	struct core_param *p = core_params;
	while (p) {
		if (!strcmp(p->name, param))
			break;
		p = p->next;
	}

	if (!p) {
		snprintf(msg, size, "No such parameter %s", param);
		return POM_ERR;
	}

	if (p->callback && (*p->callback) (value, msg, size) == POM_ERR)
		return POM_ERR;

	if (ptype_parse_val(p->value, value) == POM_ERR) {
		snprintf(msg, size, "Unable to parse %s for parameter %s", value, param);
		return POM_ERR;
	}

	core_params_serial++;

	return POM_OK;
}

struct core_param* core_param_get_head() {

	return core_params;
}

uint32_t core_param_get_serial() {

	return core_params_serial;
}


int core_param_unregister_all() {

	while (core_params) {
		struct core_param *p = core_params;
		free(p->name);
		free(p->defval);
		free(p->descr);
		core_params = core_params->next;
		free(p);
	}
	return POM_OK;
}
