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
#include "core_param.h"
#include "helper.h"

#include "version.h"

#include "xmlrpccmd_conntrack.h"
#include "xmlrpccmd_input.h"
#include "xmlrpccmd_helper.h"
#include "xmlrpccmd_rules.h"
#include "xmlrpccmd_match.h"
#include "xmlrpccmd_target.h"

#define XMLRPC_COMMANDS_NUM 7

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
	},

	{
		.name = "main.halt",
		.callback_func = xmlrpccmd_main_halt,
		.signature = "i:",
		.help = "Halt packet-o-matic",
	},

	{
		.name = "main.setPassword",
		.callback_func = xmlrpccmd_main_set_password,
		.signature = "i:,i:s",
		.help = "Set or reset the password for the XML-RPC interface",
	},

	{
		.name = "main.getLogs",
		.callback_func = xmlrpccmd_get_logs,
		.signature = "A:i",
		.help = "Get all the logs after a certain id",
	},

	{
		.name = "main.getVersion",
		.callback_func = xmlrpccmd_get_version,
		.signature = "s:",
		.help = "Get packet-o-matic version",
	}

};

int xmlrpccmd_register_all() {

	int i;

	for (i = 0; i < XMLRPC_COMMANDS_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpc_commands[i]) == POM_ERR)
			return POM_ERR;

	}

	xmlrpccmd_conntrack_register_all();
	xmlrpccmd_input_register_all();
	xmlrpccmd_helper_register_all();
	xmlrpccmd_rules_register_all();
	xmlrpccmd_match_register_all();
	xmlrpccmd_target_register_all();

	return POM_OK;
}


xmlrpc_value *xmlrpccmd_get_core_parmeters(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	struct core_param *p = core_param_get_head();

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
	

	return xmlrpc_build_value(envP, "{s:i,s:i,s:i,s:i,s:i,s:i,s:i}",
				"rules", main_config->rules_serial,
				"targets", main_config->target_serial,
				"input", main_config->input_serial,
				"core", core_param_get_serial(),
				"helper", helpers_serial,
				"conntrack", conntracks_serial,
				"logs", pom_log_get_serial());

}

xmlrpc_value *xmlrpccmd_main_halt(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	halt();

	return xmlrpc_int_new(envP, 0);

}


xmlrpc_value *xmlrpccmd_main_set_password(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char* password = NULL;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &password);
	if (envP->fault_occurred) {
		password = NULL;
		envP->fault_occurred = 0;
	}
	
	xmlrpcsrv_set_password(password);

	if (password)
		free(password);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_get_logs(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t last_id;

	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &last_id);

	xmlrpc_value *result = xmlrpc_array_new(envP);

	if (envP->fault_occurred)
		return NULL;

	pom_log_rlock();

	struct log_entry *log = pom_log_get_tail();	

	while (log && log->id >= last_id)
		log = log->prev;

	if (!log)
		log = pom_log_get_head();

	while (log) {
		xmlrpc_value *entry = xmlrpc_build_value(envP, "{s:i,s:i,s:s,s:s}",
					"id", log->id,
					"level", log->level,
					"file", log->file,
					"data", log->data);
		xmlrpc_array_append_item(envP, result, entry);
		xmlrpc_DECREF(entry);
		log = log->next;
	}

	pom_log_unlock();

	return result;


}

xmlrpc_value *xmlrpccmd_get_version(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {
	
	return xmlrpc_string_new(envP, POM_VERSION);

}

xmlrpc_value *xmlrpccmd_list_avail_modules(xmlrpc_env * const envP, char *type) {


	char **list = list_modules(type);

	if (!list) {
	        xmlrpc_faultf(envP, "No module available");
		return NULL;
	}


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
