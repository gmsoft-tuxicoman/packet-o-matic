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
#include "xmlrpccmd.h"
#include "ptype.h"

#include "main.h"
#include "helper.h"

#include "xmlrpccmd_input.h"
#include "xmlrpccmd_helper.h"
#include "xmlrpccmd_rules.h"
#include "xmlrpccmd_match.h"
#include "xmlrpccmd_target.h"

#define XMLRPC_COMMANDS_NUM 3

static struct xmlrpc_command xmlrpc_commands[XMLRPC_COMMANDS_NUM] = { 

	{
		.name = "core.getParameters",
		.callback_func = xmlrpccmd_get_core_parmeters,
		.signature = "A:",
		.help = "Return an array containing the core parameters, their value and value type",
	},

	{
		.name = "core.setParameter",
		.callback_func = xmlrpccmd_set_core_parmeter,
		.signature = "i:ss",
		.help = "Set a core parameter given a its name and value",
	},

	{
		.name = "main.getSerial",
		.callback_func = xmlrpccmd_main_get_serial,
		.signature = "A:",
		.help = "Get the serial number of each component",
	}

};

int xmlrpccmd_register_all() {

	int i;

	for (i = 0; i < XMLRPC_COMMANDS_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpc_commands[i]) == POM_ERR)
			return POM_ERR;

	}

	xmlrpccmd_input_register_all();
	xmlrpccmd_helper_register_all();
	xmlrpccmd_rules_register_all();
	xmlrpccmd_match_register_all();
	xmlrpccmd_target_register_all();

	return POM_OK;
}


xmlrpc_value *xmlrpccmd_get_core_parmeters(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	struct core_param *p = core_params;

	xmlrpc_value *result = xmlrpc_array_new(envP);
	if (envP->fault_occurred)
		return NULL;

	while (p) {
		char buff[256];
		memset(buff, 0, sizeof(buff));
		ptype_print_val(p->value, buff, sizeof(buff) - 1);
		xmlrpc_value *entry = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s}",
					"name", p->name,
					"value", buff,
					"unit", p->value->unit,
					"type", ptype_get_name(p->value->type));
		xmlrpc_array_append_item(envP, result, entry);
		xmlrpc_DECREF(entry);

		p = p->next;
	}

	return result;
	
}

xmlrpc_value *xmlrpccmd_set_core_parmeter(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name, *value;
	
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &name, &value);
	if (envP->fault_occurred)
		return NULL;

	char err[256];
	memset(err, 0, sizeof(err));

	if (core_set_param_value(name, value, err, sizeof(err) - 1) != POM_OK) {
		xmlrpc_faultf(envP, err);
		free(name);
		free(value);
		return NULL;
	}

	free(name);
	free(value);

	return xmlrpc_int_new(envP, 0);

}

xmlrpc_value *xmlrpccmd_main_get_serial(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {
	

	return xmlrpc_build_value(envP, "{s:i,s:i,s:i,s:i}",
				"rules", main_config->rules_serial,
				"input", main_config->input_serial,
				"core", core_params_serial,
				"helper", helpers_serial);

}

xmlrpc_value *xmlrpccmd_list_avail_modules(xmlrpc_env * const envP, char *type) {


	char **list = list_modules(type);

	xmlrpc_value *result = xmlrpc_array_new(envP);

	if (envP->fault_occurred)
		return NULL;

	int i;
	for (i = 0; list[i]; i++) {

		xmlrpc_value *item = xmlrpc_string_new(envP, list[i]);
		xmlrpc_array_append_item(envP, result, item);
		xmlrpc_DECREF(item);
		free(list[i]);

	}
	free(list[i]);
	free(list);

	return result;

}
