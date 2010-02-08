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


#include "common.h"
#include "xmlrpcsrv.h"
#include "xmlrpccmd.h"
#include "xmlrpccmd_target.h"
#include "ptype.h"

#include "target.h"

#include "main.h"

#define XMLRPC_TARGET_COMMANDS_NUM 12

static struct xmlrpc_command xmlrpc_target_commands[XMLRPC_TARGET_COMMANDS_NUM] = { 

	{
		.name = "target.listLoaded",
		.callback_func = xmlrpccmd_list_loaded_target,
		.signature = "A:",
		.help = "List currently loaded targets and their parameters",
	},

	{
		.name = "target.listAvail",
		.callback_func = xmlrpccmd_list_avail_target,
		.signature = "A:",
		.help = "List available targets",
	},

	{
		.name = "target.get",
		.callback_func = xmlrpccmd_get_target,
		.signature = "A:i",
		.help = "Get the targets of a rule",
	},

	{
		.name = "target.start",
		.callback_func = xmlrpccmd_start_target,
		.signature = "i:ii",
		.help = "Start a target",
	},

	{
		.name = "target.stop",
		.callback_func = xmlrpccmd_stop_target,
		.signature = "i:ii",
		.help = "Stop a target",
	},

	{
		.name = "target.add",
		.callback_func = xmlrpccmd_add_target,
		.signature = "i:is",
		.help = "Add a target to a rule",
	},

	{
		.name = "target.remove",
		.callback_func = xmlrpccmd_remove_target,
		.signature = "i:ii",
		.help = "Remove a target from a rule",
	},

	{
		.name = "target.setMode",
		.callback_func = xmlrpccmd_set_target_mode,
		.signature = "i:iis",
		.help = "Set the target mode given its name",
	},

	{
		.name = "target.setParameter",
		.callback_func = xmlrpccmd_set_target_parameter,
		.signature = "i:iiss",
		.help = "Set a target parameter given its name and value",
	},

	{
		.name = "target.setDescription",
		.callback_func = xmlrpccmd_set_target_description,
		.signature = "i:iis",
		.help = "Set a target description",
	},

	{
		.name = "target.load",
		.callback_func = xmlrpccmd_load_target,
		.signature = "i:s",
		.help = "List a target given its name",
	},

	{
		.name = "target.unload",
		.callback_func = xmlrpccmd_unload_target,
		.signature = "i:s",
		.help = "Unload a target given its name",
	},
};

int xmlrpccmd_target_register_all() {

	int i;

	for (i = 0; i < XMLRPC_TARGET_COMMANDS_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpc_target_commands[i]) == POM_ERR)
			return POM_ERR;

	}

	return POM_OK;
}

xmlrpc_value *xmlrpccmd_list_loaded_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_value *result = xmlrpc_array_new(envP);

	if (envP->fault_occurred)
		return NULL;

	target_lock(0);

	int i;
	for (i = 0; i < MAX_TARGET; i++) {
		
		if (!targets[i])
			continue;
		xmlrpc_value *modes = xmlrpc_array_new(envP);

		struct target_mode *m = targets[i]->modes;
		while (m) {


			struct target_param_reg *p = m->params;
			xmlrpc_value *params = xmlrpc_array_new(envP);

			while (p) {
				
				xmlrpc_value *param = xmlrpc_build_value(envP, "{s:s,s:s,s:s}",
							"name", p->name,
							"defval", p->defval,
							"descr", p->descr);
				xmlrpc_array_append_item(envP, params, param);
				xmlrpc_DECREF(param);

				p = p->next;
			}

			xmlrpc_value *mode = xmlrpc_build_value(envP, "{s:s,s:s,s:A}",
						"name", m->name,
						"descr", m->descr,
						"params", params);
			xmlrpc_DECREF(params);
			xmlrpc_array_append_item(envP, modes, mode);
			xmlrpc_DECREF(mode);
			m = m->next;

		}

		xmlrpc_value *target = xmlrpc_build_value(envP, "{s:s,s:i,s:A}",
						"name", targets[i]->name,
						"refcount", targets[i]->refcount,
						"modes", modes);

		xmlrpc_DECREF(modes);
	
		xmlrpc_array_append_item(envP, result, target);
		xmlrpc_DECREF(target);
	}

	target_unlock();

	return result;
}

xmlrpc_value *xmlrpccmd_get_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t rule_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &rule_id);

	if (envP->fault_occurred)
		return NULL;

	main_config_rules_lock(0);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		return NULL;
	}

	struct target *t = rl->target;

	xmlrpc_value *result = xmlrpc_array_new(envP);

	while (t) {
		target_lock_instance(t, 0);
		xmlrpc_value *params = xmlrpc_array_new(envP);

		if (t->mode) {
			struct target_param_reg *tp = t->mode->params;
			while (tp) {
				
				char buff[256];
				memset(buff, 0, sizeof(buff));
				struct ptype *value = target_get_param_value(t, tp->name);
				ptype_print_val(value , buff, sizeof(buff));

				xmlrpc_value *param = xmlrpc_build_value(envP, "{s:s,s:s,s:s}",
							"name", tp->name,
							"value", buff,
							"type", ptype_get_name(value->type));
				xmlrpc_array_append_item(envP, params, param);
				xmlrpc_DECREF(param);
				tp = tp->next;

			}
		}
	
		char *mode_name = "none";
		if (t->mode)
			mode_name = t->mode->name;

		char *description = "";
		if (t->description)
			description = t->description;

		xmlrpc_value *target = xmlrpc_build_value(envP, "{s:s,s:b,s:s,s:i,s:i,s:s,s:A}",
				"name", target_get_name(t->type),
				"started", t->started,
				"mode", mode_name,
				"uid", t->uid,
				"serial", t->serial,
				"description", description,
				"params", params);
		xmlrpc_DECREF(params);


		xmlrpc_array_append_item(envP, result, target);
		xmlrpc_DECREF(target);
		target_unlock_instance(t);

		t = t->next;
	}


	main_config_rules_unlock();

	return result;

}


xmlrpc_value *xmlrpccmd_add_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *target_name;
	uint32_t rule_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(is)", &rule_id, &target_name);

	if (envP->fault_occurred)
		return NULL;


	main_config_rules_lock(1);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		free(target_name);
		return NULL;
	}

	target_lock(1);
	int target_type = target_register(target_name);
	free(target_name);

	if (target_type == POM_ERR) {
		target_unlock();
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Target does not exists");
		return NULL;
	}

	struct target *t = target_alloc(target_type);
	target_unlock();

	if (!t) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Error while allocating the target");
		return NULL;
	}

	if (!rl->target)
		rl->target = t;
	else {
		struct target *tmpt = rl->target;
		while (tmpt->next)
			tmpt = tmpt->next;
		tmpt->next = t;
		t->prev = tmpt;
	}

	t->parent_serial = &rl->target_serial;
	rl->target_serial++;
	main_config->target_serial++;

	main_config_rules_unlock();

	return xmlrpc_int_new(envP, t->uid);

}

xmlrpc_value *xmlrpccmd_remove_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t rule_id, target_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(ii)", &rule_id, &target_id);

	if (envP->fault_occurred)
		return NULL;


	main_config_rules_lock(1);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		return NULL;
	}

	struct target *t = rl->target;
	while (t && t->uid != target_id)
		t = t->next;

	if (!t) {
		main_config_rules_unlock();
		xmlrpc_faultf( envP, "Target not found");
		return NULL;
	}

	target_lock_instance(t, 1);

	if (t->started) {
		target_close(t);
	} else {
		rl->target_serial++;
		main_config->target_serial++;
	}

	if (t->prev)
		t->prev->next = t->next;
	else
		rl->target = t-> next;

	if (t->next)
		t->next->prev = t->prev;

	target_cleanup_module(t);

	main_config_rules_unlock();

	return xmlrpc_int_new(envP, 0);

}

xmlrpc_value *xmlrpccmd_start_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t rule_id, target_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(ii)", &rule_id, &target_id);

	if (envP->fault_occurred)
		return NULL;


	main_config_rules_lock(0);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		return NULL;
	}

	struct target *t = rl->target;
	while (t && t->uid != target_id)
		t = t->next;

	if (!t) {
		main_config_rules_unlock();
		xmlrpc_faultf( envP, "Target not found");
		return NULL;
	}

	target_lock_instance(t, 1);
	main_config_rules_unlock();

	if (t->started) {
		target_unlock_instance(t);
		xmlrpc_faultf(envP, "Target already started");
		return NULL;
	}

	if (target_open(t) == POM_ERR) {
		target_unlock_instance(t);
		xmlrpc_faultf(envP, "Error while starting the target");
		return NULL;
	}

	target_unlock_instance(t);
	return xmlrpc_int_new(envP, t->uid);

}

xmlrpc_value *xmlrpccmd_stop_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t rule_id, target_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(ii)", &rule_id, &target_id);

	if (envP->fault_occurred)
		return NULL;


	main_config_rules_lock(0);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		return NULL;
	}

	struct target *t = rl->target;
	while (t && t->uid != target_id)
		t = t->next;

	if (!t) {
		main_config_rules_unlock();
		xmlrpc_faultf( envP, "Target not found");
		return NULL;
	}

	target_lock_instance(t, 1);
	main_config_rules_unlock();

	if (!t->started) {
		target_unlock_instance(t);
		xmlrpc_faultf(envP, "Target not yet started");
		return NULL;
	}

	if (target_close(t) == POM_ERR) {
		target_unlock_instance(t);
		xmlrpc_faultf(envP, "Error while stopping the target");
		return NULL;
	}

	target_unlock_instance(t);
	return xmlrpc_int_new(envP, t->uid);

}

xmlrpc_value *xmlrpccmd_set_target_mode(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *mode_name;
	uint32_t rule_id, target_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(iis)", &rule_id, &target_id, &mode_name);

	if (envP->fault_occurred)
		return NULL;


	main_config_rules_lock(0);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		free(mode_name);
		return NULL;
	}

	struct target *t = rl->target;
	while (t && t->uid != target_id)
		t = t->next;

	if (!t) {
		xmlrpc_faultf( envP, "Target not found");
		free(mode_name);
		return NULL;
	}

	target_lock_instance(t, 1);
	main_config_rules_unlock();

	if (t->started) {
		target_unlock_instance(t);
		free(mode_name);
		xmlrpc_faultf(envP, "Target must be stopped to change its mode");
		return NULL;
	}

	if (target_set_mode(t, mode_name) == POM_ERR) {
		target_unlock_instance(t);
		xmlrpc_faultf(envP, "No mode \"%s\" for this target", mode_name);
		free(mode_name);
		return NULL;
	}

	main_config->target_serial++;
	rl->target_serial++;
	t->serial++;

	free(mode_name);
	target_unlock_instance(t);
	return xmlrpc_int_new(envP, t->uid);

}

xmlrpc_value *xmlrpccmd_set_target_parameter(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *param_name, *value;
	uint32_t rule_id, target_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(iiss)", &rule_id, &target_id, &param_name, &value);

	if (envP->fault_occurred)
		return NULL;


	main_config_rules_lock(0);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		free(param_name);
		free(value);
		return NULL;
	}

	struct target *t = rl->target;
	while (t && t->uid != target_id)
		t = t->next;

	if (!t) {
		xmlrpc_faultf( envP, "Target not found");
		free(param_name);
		free(value);
		return NULL;
	}

	target_lock_instance(t, 1);
	main_config_rules_unlock();

	struct ptype *p = target_get_param_value(t, param_name);
	
	if (!p) {
		target_unlock_instance(t);
		xmlrpc_faultf(envP, "No parameter %s for the target", param_name);
		free(param_name);
		free(value);
		return NULL;
	}
	free(param_name);

	if (ptype_parse_val(p, value) != POM_OK) {
		target_unlock_instance(t);
		xmlrpc_faultf(envP, "Could not parse \"%s\"", value);
		free(value);
		return NULL;
	}

	main_config->target_serial++;
	rl->target_serial++;
	t->serial++;

	target_unlock_instance(t);

	free(value);

	return xmlrpc_int_new(envP, t->uid);
}

xmlrpc_value *xmlrpccmd_set_target_description(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *descr;
	uint32_t rule_id, target_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(iis)", &rule_id, &target_id, &descr);

	if (envP->fault_occurred)
		return NULL;


	main_config_rules_lock(0);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		free(descr);
		return NULL;
	}

	struct target *t = rl->target;
	while (t && t->uid != target_id)
		t = t->next;

	if (!t) {
		xmlrpc_faultf( envP, "Target not found");
		free(descr);
		return NULL;
	}

	target_lock_instance(t, 1);
	main_config_rules_unlock();

	if (t->description)
		free(t->description);

	if (strlen(descr)) {
		t->description = descr;
	} else {
		free(descr);
		t->description = NULL;
	}

	main_config->target_serial++;
	rl->target_serial++;
	t->serial++;

	target_unlock_instance(t);
	return xmlrpc_int_new(envP, t->uid);

}

xmlrpc_value *xmlrpccmd_load_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	
	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	target_lock(1);

	int id = target_get_type(name);
	if (id != POM_ERR) {
		target_unlock();
		xmlrpc_faultf(envP, "Target %s is already registered", name);
		free(name);
		return NULL;
	}

	if (target_register(name) == POM_ERR) {
		target_unlock();
		xmlrpc_faultf(envP, "Error while loading target %s", name);
		free(name);
		return NULL;
	}

	target_unlock();

	free(name);
	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_unload_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	target_lock(1);
	int id = target_get_type(name);


	if (id == POM_ERR) {
		target_unlock();
		xmlrpc_faultf(envP, "Target %s is not loaded", name);
		free(name);
		return NULL;
	}

	if (target_unregister(id) == POM_ERR) {
		target_unlock();
		xmlrpc_faultf(envP, "Error while unloading target %s", name);
		free(name);
		return NULL;
	}

	target_unlock();

	free(name);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_list_avail_target(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	return xmlrpccmd_list_avail_modules(envP, "target");

}
