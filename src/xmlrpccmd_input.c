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


#include "common.h"
#include "xmlrpcsrv.h"
#include "xmlrpccmd_input.h"
#include "ptype.h"

#include "main.h"

#define XMLRPC_INPUT_COMMANDS_NUM 9

static struct xmlrpc_command xmlrpc_input_commands[XMLRPC_INPUT_COMMANDS_NUM] = { 

	{
		.name = "input.get",
		.callback_func = xmlrpccmd_get_input,
		.signature = "A:,n:",
		.help = "Get all the information related to the current input or nil if no input is configured",
	},
	{
		.name = "input.start",
		.callback_func = xmlrpccmd_start_input,
		.signature = "n:",
		.help = "Start the input",
	},

	{
		.name = "input.stop",
		.callback_func = xmlrpccmd_stop_input,
		.signature = "n:",
		.help = "Stop the input",
	},

	{
		.name = "input.setType",
		.callback_func = xmlrpccmd_set_input_type,
		.signature = "n:s",
		.help = "Set the type of the input",
	},

	{
		.name = "input.setMode",
		.callback_func = xmlrpccmd_set_input_mode,
		.signature = "n:s",
		.help = "Set the mode of the input",
	},

	{
		.name = "input.setParameter",
		.callback_func = xmlrpccmd_set_input_parameter,
		.signature = "n:ss",
		.help = "Set a value for an input parameter",

	},

	{
		.name = "input.listLoaded",
		.callback_func = xmlrpccmd_list_loaded_input,
		.signature = "A:",
		.help = "List all the loaded inputs",
	},

	{
		.name = "input.load",
		.callback_func = xmlrpccmd_load_input,
		.signature = "n:s",
		.help = "Load an input given its name",

	},

	{
		.name = "input.unload",
		.callback_func = xmlrpccmd_unload_input,
		.signature = "n:s",
		.help = "Unload an input given its name",

	},
};

int xmlrpccmd_input_register_all() {

	int i;

	for (i = 0; i < XMLRPC_INPUT_COMMANDS_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpc_input_commands[i]) == POM_ERR)
			return POM_ERR;

	}

	return POM_OK;
}

xmlrpc_value *xmlrpccmd_get_input(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	struct input* i = main_config->input;

	if (!i)
		return xmlrpc_nil_new(envP);

	xmlrpc_value *params = xmlrpc_array_new(envP);
	if (envP->fault_occurred)
		return NULL;

	struct input_param *p = i->mode->params;
	while (p) {
		char buff[256];
		ptype_print_val(p->value, buff, sizeof(buff) - 1);
		xmlrpc_value *entry = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s}",
					"name", p->name,
					"value", buff,
					"unit", p->value->unit,
					"type", ptype_get_name(p->value->type));
		xmlrpc_array_append_item(envP, params, entry);
		xmlrpc_DECREF(entry);
		p = p->next;
	}

	xmlrpc_value *result = xmlrpc_build_value(envP, "{s:s,s:s,s:b,s:A}",
					"type", input_get_name(i->type),
					"mode", i->mode->name,
					"running", i->running,
					"parameters", params);

	xmlrpc_DECREF(params);

	if (envP->fault_occurred)
		return NULL;

	return result;
}

xmlrpc_value *xmlrpccmd_start_input(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	if (rbuf->state != rb_state_closed) {
		xmlrpc_faultf(envP, "Input already started");
		return NULL;
	}

	if (!main_config->input) {
		xmlrpc_faultf(envP, "No input configured yet");
		return NULL;
	}

	if (start_input(rbuf) == POM_ERR) {
		xmlrpc_faultf(envP, "Error while starting the input");
		return NULL;
	}

	return xmlrpc_nil_new(envP);
}

xmlrpc_value *xmlrpccmd_stop_input(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	if (rbuf->state == rb_state_closed) {
		xmlrpc_faultf(envP, "Input already stopped");
		return NULL;
	}

	if (stop_input(rbuf) == POM_ERR) {
		xmlrpc_faultf(envP, "Error while starting the input");
		return NULL;
	}

	return xmlrpc_nil_new(envP);
}

xmlrpc_value *xmlrpccmd_set_input_type(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	if (envP->fault_occurred)
		return NULL;

	if (rbuf->i && rbuf->i->running) {
		xmlrpc_faultf(envP, "Input is running. You need to stop it before doing any change");
		return NULL;
	}

	if (pthread_mutex_lock(&rbuf->mutex)) {
		xmlrpc_faultf(envP, "Error while locking the buffer mutex");
		return NULL;
	}

	char *type;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &type);

	if (rbuf->i && !strcmp(type, input_get_name(rbuf->i->type))) {
		xmlrpc_faultf(envP, "Input type is already %s", type);
		free(type);
		pthread_mutex_unlock(&rbuf->mutex);
		return NULL;
	}

	input_lock(1);

	struct input *i;
	int input_type = input_register(type);
	if (input_type == POM_ERR) {
		input_unlock();
		xmlrpc_faultf(envP, "Unable to register input %s", type);
		free(type);
		pthread_mutex_unlock(&rbuf->mutex);
		return POM_OK;
	}

	i = input_alloc(input_type);

	// we can safely unlock since our input has a positive refcount
	input_unlock();

	if (!i) {
		xmlrpc_faultf(envP, "Unable to allocate input %s", type);
		free(type);
		pthread_mutex_unlock(&rbuf->mutex);
		return NULL;
	}

	free(type);

	if (rbuf->i)
		input_cleanup(rbuf->i);
	rbuf->i = i;
	main_config->input = i;

	if (pthread_mutex_unlock(&rbuf->mutex)) {
		xmlrpc_faultf(envP, "Error while unlocking the buffer mutex");
		return NULL;
	}

	return xmlrpc_nil_new(envP);
}

xmlrpc_value *xmlrpccmd_set_input_mode(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	if (!rbuf->i) {
		xmlrpc_faultf(envP, "No input configured yet");
		return NULL;
	}

	if (rbuf->i->running) {
		xmlrpc_faultf(envP, "Input is running. You need to stop it before doing any change");
		return NULL;
	}

	char *mode;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &mode);

	if (envP->fault_occurred)
		return NULL;

	if (input_set_mode(rbuf->i, mode) != POM_OK) {
		xmlrpc_faultf(envP, "No mode %s for this input", mode);
		free(mode);
		return NULL;
	}
	free(mode);
	
	return xmlrpc_nil_new(envP);
}

xmlrpc_value *xmlrpccmd_set_input_parameter(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	if (!rbuf->i) {
		xmlrpc_faultf(envP, "No input configured yet");
		return NULL;
	}

	if (rbuf->i->running) {
		xmlrpc_faultf(envP, "Input is running. You need to stop it before doing any change");
		return NULL;
	}

	char *name, *value;
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &name, &value);

	if (envP->fault_occurred)
		return NULL;

	struct input_param *p = rbuf->i->mode->params;
	while (p) {
		if (!strcmp(p->name, name))
			break;
		p = p->next;
	}

	if (!p) {
		xmlrpc_faultf(envP, "Parameter %s doesn't exists", name);
		free(name);
		free(value);
		return NULL;
	}

	free(name);

	if (ptype_parse_val(p->value, value) != POM_OK) {
		xmlrpc_faultf(envP, "Could not parse \"%s\"", value);
		free(value);
		return NULL;
	}

	free(value);

	return xmlrpc_nil_new(envP);
}

xmlrpc_value *xmlrpccmd_list_loaded_input(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	
	xmlrpc_value *result = xmlrpc_array_new(envP);
	if (envP->fault_occurred)
		return NULL;

	input_lock(0);

	int i;
	for (i = 0; i < MAX_INPUT; i++) {

		if (!inputs[i])
			continue;

		struct input_mode *m = inputs[i]->modes;
		xmlrpc_value *modes = xmlrpc_array_new(envP);

		while (m) {

			struct input_param *p = m->params;
			xmlrpc_value *params = xmlrpc_array_new(envP);

			while (p) {
				xmlrpc_value *param = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s}",
							"name", p->name,
							"unit", p->value->unit,
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

		xmlrpc_value *input = xmlrpc_build_value(envP, "{s:s,s:A}",
						"name", inputs[i]->name,
						"modes", modes);
		xmlrpc_DECREF(modes);

		xmlrpc_array_append_item(envP, result, input);
		xmlrpc_DECREF(input);

	}

	input_unlock();

	if (envP->fault_occurred)
		return NULL;

	return result;


}

xmlrpc_value *xmlrpccmd_load_input(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	
	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	input_lock(1);

	if (input_get_type(name) != POM_ERR) {
		input_unlock();
		xmlrpc_faultf(envP, "Input %s is already registered", name);
		free(name);
		return NULL;
	}

	if (input_register(name) == POM_ERR) {
		input_unlock();
		xmlrpc_faultf(envP, "Error while loading input %s", name);
		free(name);
		return NULL;
	}
	input_unlock();

	free(name);
	return xmlrpc_nil_new(envP);
}

xmlrpc_value *xmlrpccmd_unload_input(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	
	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	input_lock(1);

	int id = input_get_type(name);

	if (id == POM_ERR) {
		input_unlock();
		xmlrpc_faultf(envP, "Input %s is not loaded", name);
		free(name);
		return NULL;
	}

	if (input_unregister(id) == POM_ERR) {
		input_unlock();
		xmlrpc_faultf(envP, "Error while unloading input %s", name);
		free(name);
		return NULL;
	}
	input_unlock();

	free(name);

	return xmlrpc_nil_new(envP);
}
