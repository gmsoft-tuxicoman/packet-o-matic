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
#include "xmlrpccmd_match.h"
#include "ptype.h"

#include "match.h"

#include "main.h"

#define XMLRPC_MATCH_COMMANDS_NUM 4

static struct xmlrpc_command xmlrpc_match_commands[XMLRPC_MATCH_COMMANDS_NUM] = { 

	{
		.name = "match.listLoaded",
		.callback_func = xmlrpccmd_list_loaded_match,
		.signature = "A:",
		.help = "List currently loaded matchs and their fields",
	},

	{
		.name = "match.listAvail",
		.callback_func = xmlrpccmd_list_avail_match,
		.signature = "A:",
		.help = "List available matches",
	},

	{
		.name = "match.load",
		.callback_func = xmlrpccmd_load_match,
		.signature = "i:",
		.help = "List a match given its name",
	},

	{
		.name = "match.unload",
		.callback_func = xmlrpccmd_unload_match,
		.signature = "i:",
		.help = "Unload a match given its name",
	},
};

int xmlrpccmd_match_register_all() {

	int i;

	for (i = 0; i < XMLRPC_MATCH_COMMANDS_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpc_match_commands[i]) == POM_ERR)
			return POM_ERR;

	}

	return POM_OK;
}

xmlrpc_value *xmlrpccmd_list_loaded_match(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_value *result = xmlrpc_array_new(envP);

	if (envP->fault_occurred)
		return NULL;

	match_lock(0);

	int i;
	for (i = 0; i < MAX_MATCH; i++) {
		
		if (!matches[i])
			continue;

		xmlrpc_value *fields = xmlrpc_array_new(envP);

		int j;
		for (j = 0; j < MAX_LAYER_FIELDS; j++) {
			
			struct match_field_reg *f = matches[i]->fields[j];

			if (!f)
				continue;


			xmlrpc_value *field = xmlrpc_build_value(envP, "{s:s,s:s,s:s}",
						"name", f->name,
						"type", ptype_get_name(f->type->type),
						"descr", f->descr);
			xmlrpc_array_append_item(envP, fields, field);
			xmlrpc_DECREF(field);

		}

		xmlrpc_value *match = xmlrpc_build_value(envP, "{s:s,s:i,s:A}",
						"name", matches[i]->name,
						"refcount", matches[i]->refcount,
						"fields", fields);

		xmlrpc_array_append_item(envP, result, match);
		xmlrpc_DECREF(match);
	}

	match_unlock();

	return result;
}


xmlrpc_value *xmlrpccmd_load_match(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	
	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	int id = match_get_type(name);

	match_lock(1);
	if (matches[id]) {
		match_unlock();
		xmlrpc_faultf(envP, "Match %s is already registered", name);
		free(name);
		return NULL;
	}

	if (match_register(name) == POM_ERR) {
		match_unlock();
		xmlrpc_faultf(envP, "Error while loading match %s", name);
		free(name);
		return NULL;
	}

	match_unlock();

	free(name);
	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_unload_match(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name;

	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	int id = match_get_type(name);


	match_lock(1);
	if (id == POM_ERR) {
		match_unlock();
		xmlrpc_faultf(envP, "Match %s is not loaded", name);
		free(name);
		return NULL;
	}

	if (match_unregister(id) == POM_ERR) {
		match_unlock();
		xmlrpc_faultf(envP, "Error while unloading match %s", name);
		free(name);
		return NULL;
	}

	match_unlock();

	free(name);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_list_avail_match(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	return xmlrpccmd_list_avail_modules(envP, "match");

}
