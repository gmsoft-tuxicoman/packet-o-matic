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
#include "xmlrpccmd_helper.h"
#include "ptype.h"

#include "helper.h"

#include "main.h"

#define XMLRPC_HELPER_COMMANDS_NUM 4

static struct xmlrpc_command xmlrpc_helper_commands[XMLRPC_HELPER_COMMANDS_NUM] = { 

	{
		.name = "helper.listLoaded",
		.callback_func = xmlrpccmd_list_loaded_helper,
		.signature = "A:",
		.help = "List currently loaded helpers and their parameters",
	},

	{
		.name = "helper.setParameter",
		.callback_func = xmlrpccmd_set_helper_parameter,
		.signature = "n:sss",
		.help = "Set an helper given its name and value",
	},

	{
		.name = "helper.load",
		.callback_func = xmlrpccmd_load_helper,
		.signature = "n:",
		.help = "List a helper given its name",
	},

	{
		.name = "helper.unload",
		.callback_func = xmlrpccmd_unload_helper,
		.signature = "n:",
		.help = "Unload a helper given its name",
	},
};

int xmlrpccmd_helper_register_all() {

	int i;

	for (i = 0; i < XMLRPC_HELPER_COMMANDS_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpc_helper_commands[i]) == POM_ERR)
			return POM_ERR;

	}

	return POM_OK;
}

xmlrpc_value *xmlrpccmd_list_loaded_helper(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_value *result = xmlrpc_array_new(envP);

	if (envP->fault_occurred)
		return NULL;

	helper_lock(0);

	int i;
	for (i = 0; i < MAX_HELPER; i++) {
		
		if (!helpers[i])
			continue;

		struct helper_param *p = helpers[i]->params;
		xmlrpc_value *params = xmlrpc_array_new(envP);

		while (p) {
			
			char buff[256];
			ptype_print_val(p->value, buff, sizeof(buff) - 1);
			xmlrpc_value *param = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s}",
						"name", p->name,
						"defval", p->defval,
						"descr", p->descr,
						"value", buff);
			xmlrpc_array_append_item(envP, params, param);
			xmlrpc_DECREF(param);

			p = p->next;
		}

		xmlrpc_value *helper = xmlrpc_build_value(envP, "{s:s,s:A}",
						"name", match_get_name(helpers[i]->type),
						"params", params);

		xmlrpc_array_append_item(envP, result, helper);
		xmlrpc_DECREF(helper);
	}

	helper_unlock();

	return result;
}

xmlrpc_value *xmlrpccmd_set_helper_parameter(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name, *param_name, *value;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &name, &param_name, &value);

	if (envP->fault_occurred)
		return NULL;

	int id = match_get_type(name);

	helper_lock(1);
	if (id == POM_ERR || !helpers[id]) {
		helper_unlock();
		xmlrpc_faultf(envP, "Helper %s does not exists", name);
		free(name);
		free(param_name);
		free(value);
		return NULL;
	}

	struct helper_param *p = helper_get_param(id, param_name);
	if (!p) {
		helper_unlock();
		xmlrpc_faultf(envP, "Parameter %s doesn't exists", name);
		free(name);
		free(param_name);
		free(value);
		return NULL;
	}

	free(param_name);
	free(name);

	if (ptype_parse_val(p->value, value) != POM_OK) {
		helper_unlock();
		xmlrpc_faultf(envP, "Could not parse \"%s\"", value);
		free(value);
		return NULL;
	}
	helper_unlock();

	free(value);

	return xmlrpc_nil_new(envP);
}

xmlrpc_value *xmlrpccmd_load_helper(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	
	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	int id = match_get_type(name);

	if (id == POM_ERR) {
		xmlrpc_faultf(envP, "Cannot load helper %s : corresponding match not loaded yet", name);
		free(name);
		return NULL;
	}
	
	helper_lock(1);

	if (helpers[id]) {
		helper_unlock();
		xmlrpc_faultf(envP, "Helper %s is already registered", name);
		free(name);
		return NULL;
	}

	if (helper_register(name) == POM_ERR) {
		helper_unlock();
		xmlrpc_faultf(envP, "Error while loading helper %s", name);
		free(name);
		reader_process_unlock();
		return NULL;
	}

	helper_unlock();

	free(name);
	return xmlrpc_nil_new(envP);
}

xmlrpc_value *xmlrpccmd_unload_helper(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	int id = match_get_type(name);

	helper_lock(1);

	if (id == POM_ERR || !helpers[id]) {
		helper_unlock();
		xmlrpc_faultf(envP, "Helper %s is not loaded", name);
		free(name);
		return NULL;
	}

	if (helper_unregister(id) == POM_ERR) {
		helper_unlock();
		xmlrpc_faultf(envP, "Error while unloading helper %s", name);
		free(name);
		reader_process_unlock();
		return NULL;
	}

	helper_unlock();

	free(name);

	return xmlrpc_nil_new(envP);
}
