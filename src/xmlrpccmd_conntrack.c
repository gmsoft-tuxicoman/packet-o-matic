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
#include "xmlrpccmd_conntrack.h"
#include "ptype.h"

#include "conntrack.h"

#include "main.h"

#define XMLRPC_CONNTRACK_COMMANDS_NUM 5

static struct xmlrpc_command xmlrpc_conntrack_commands[XMLRPC_CONNTRACK_COMMANDS_NUM] = { 

	{
		.name = "conntrack.listLoaded",
		.callback_func = xmlrpccmd_list_loaded_conntrack,
		.signature = "A:",
		.help = "List currently loaded conntracks and their parameters",
	},

	{
		.name = "conntrack.listAvail",
		.callback_func = xmlrpccmd_list_avail_conntrack,
		.signature = "A:",
		.help = "List available conntracks",
	},

	{
		.name = "conntrack.setParameter",
		.callback_func = xmlrpccmd_set_conntrack_parameter,
		.signature = "i:sss",
		.help = "Set an conntrack given its name and value",
	},

	{
		.name = "conntrack.load",
		.callback_func = xmlrpccmd_load_conntrack,
		.signature = "i:",
		.help = "List a conntrack given its name",
	},

	{
		.name = "conntrack.unload",
		.callback_func = xmlrpccmd_unload_conntrack,
		.signature = "i:",
		.help = "Unload a conntrack given its name",
	},
};

int xmlrpccmd_conntrack_register_all() {

	int i;

	for (i = 0; i < XMLRPC_CONNTRACK_COMMANDS_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpc_conntrack_commands[i]) == POM_ERR)
			return POM_ERR;

	}

	return POM_OK;
}

xmlrpc_value *xmlrpccmd_list_loaded_conntrack(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_value *result = xmlrpc_array_new(envP);

	if (envP->fault_occurred)
		return NULL;

	conntrack_lock(0);

	int i;
	for (i = 0; i < MAX_HELPER; i++) {
		
		if (!conntracks[i])
			continue;

		struct conntrack_param *p = conntracks[i]->params;
		xmlrpc_value *params = xmlrpc_array_new(envP);

		while (p) {
			
			char buff[256];
			ptype_print_val(p->value, buff, sizeof(buff) - 1);
			xmlrpc_value *param = xmlrpc_build_value(envP, "{s:s,s:s,s:s,s:s,s:s,s:s}",
						"name", p->name,
						"defval", p->defval,
						"descr", p->descr,
						"value", buff,
						"type", ptype_get_name(p->value->type),
						"unit", p->value->unit);
			xmlrpc_array_append_item(envP, params, param);
			xmlrpc_DECREF(param);

			p = p->next;
		}

		xmlrpc_value *conntrack = xmlrpc_build_value(envP, "{s:s,s:A}",
						"name", match_get_name(conntracks[i]->type),
						"params", params);

		xmlrpc_array_append_item(envP, result, conntrack);
		xmlrpc_DECREF(conntrack);
	}

	conntrack_unlock();

	return result;
}

xmlrpc_value *xmlrpccmd_set_conntrack_parameter(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name, *param_name, *value;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &name, &param_name, &value);

	if (envP->fault_occurred)
		return NULL;

	int id = match_get_type(name);

	conntrack_lock(1);
	if (id == POM_ERR || !conntracks[id]) {
		conntrack_unlock();
		xmlrpc_faultf(envP, "Conntrack %s does not exists", name);
		free(name);
		free(param_name);
		free(value);
		return NULL;
	}

	struct conntrack_param *p = conntrack_get_param(id, param_name);
	if (!p) {
		conntrack_unlock();
		xmlrpc_faultf(envP, "Parameter %s doesn't exists", name);
		free(name);
		free(param_name);
		free(value);
		return NULL;
	}

	free(param_name);
	free(name);

	if (ptype_parse_val(p->value, value) != POM_OK) {
		conntrack_unlock();
		xmlrpc_faultf(envP, "Could not parse \"%s\"", value);
		free(value);
		return NULL;
	}
	conntracks_serial++;
	conntrack_unlock();

	free(value);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_load_conntrack(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	
	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	int id = match_get_type(name);

	if (id == POM_ERR) {
		xmlrpc_faultf(envP, "Cannot load conntrack %s : corresponding match not loaded yet", name);
		free(name);
		return NULL;
	}
	
	conntrack_lock(1);

	if (conntracks[id]) {
		conntrack_unlock();
		xmlrpc_faultf(envP, "Conntrack %s is already registered", name);
		free(name);
		return NULL;
	}

	if (conntrack_register(name) == POM_ERR) {
		conntrack_unlock();
		xmlrpc_faultf(envP, "Error while loading conntrack %s", name);
		free(name);
		return NULL;
	}

	conntrack_unlock();

	free(name);
	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_unload_conntrack(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	int id = match_get_type(name);

	conntrack_lock(1);

	if (id == POM_ERR || !conntracks[id]) {
		conntrack_unlock();
		xmlrpc_faultf(envP, "Conntrack %s is not loaded", name);
		free(name);
		return NULL;
	}

	if (conntrack_unregister(id) == POM_ERR) {
		conntrack_unlock();
		xmlrpc_faultf(envP, "Error while unloading conntrack %s", name);
		free(name);
		return NULL;
	}

	conntrack_unlock();

	free(name);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_list_avail_conntrack(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	return xmlrpccmd_list_avail_modules(envP, "conntrack");

}
