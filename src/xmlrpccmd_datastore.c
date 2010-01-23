/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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
#include "xmlrpccmd_datastore.h"
#include "mgmtcmd_datastore.h"
#include "main.h"
#include "datastore.h"


#define XMLRPC_DATASTORE_COMMANDS_NUM 13

static struct xmlrpc_command xmlrpc_datastore_commands[XMLRPC_DATASTORE_COMMANDS_NUM] = { 

	{
		.name = "datastore.listLoaded",
		.callback_func = xmlrpccmd_list_loaded_datastore,
		.signature = "A:",
		.help = "List currently loaded datastores and their parameters",
	},

	{
		.name = "datastore.listAvail",
		.callback_func = xmlrpccmd_list_avail_datastore,
		.signature = "A:",
		.help = "List available datastores",
	},

	{
		.name = "datastore.get",
		.callback_func = xmlrpccmd_get_datastore,
		.signature = "A:",
		.help = "Get the datastores",
	},

	{
		.name = "datastore.add",
		.callback_func = xmlrpccmd_add_datastore,
		.signature = "i:ss",
		.help = "Add a datastore and get it's UID",
	},

	{
		.name = "datastore.remove",
		.callback_func = xmlrpccmd_remove_datastore,
		.signature = "i:s",
		.help = "Remove a datastore",
	},

	{
		.name = "datastore.start",
		.callback_func = xmlrpccmd_start_datastore,
		.signature = "i:s",
		.help = "Start a datastore",

	},
	
	{
		.name = "datastore.stop",
		.callback_func = xmlrpccmd_stop_datastore,
		.signature = "i:s",
		.help = "Stop a datastore",

	},

	{
		.name = "datastore.setParameter",
		.callback_func = xmlrpccmd_set_datastore_parameter,
		.signature = "i:sss",
		.help = "Set a value for a datastore parameter",
	},
	
	{
		.name = "datastore.setDescription",
		.callback_func = xmlrpccmd_set_datastore_description,
		.signature = "i:sss",
		.help = "Set the description of a datastore",
	},

	{
		.name = "datastore.load",
		.callback_func = xmlrpccmd_load_datastore,
		.signature = "i:s",
		.help = "Load a datastore module",
	},

	{
		.name = "datastore.unload",
		.callback_func = xmlrpccmd_unload_datastore,
		.signature = "i:s",
		.help = "Unload a datastore module",
	},

	{
		.name = "datastore.listDataset",
		.callback_func = xmlrpccmd_datastore_list_dataset,
		.signature = "i:s",
		.help = "List the datasets from a datastore",
	},

	{
		.name = "datastore.destroyDataset",
		.callback_func = xmlrpccmd_datastore_destroy_dataset,
		.signature = "i:ss",
		.help = "Destroy a datasets from a datastore",
	},
};

int xmlrpccmd_datastore_register_all() {

	int i;

	for (i = 0; i < XMLRPC_DATASTORE_COMMANDS_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpc_datastore_commands[i]) == POM_ERR)
			return POM_ERR;

	}

	return POM_OK;
}

xmlrpc_value *xmlrpccmd_list_loaded_datastore(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_value *result = xmlrpc_array_new(envP);

	if (envP->fault_occurred)
		return NULL;

	datastore_lock(0);

	int i;
	for (i = 0; i < MAX_DATASTORE; i++) {

		if (!datastores[i])
			continue;

		struct datastore_param_reg *p = datastores[i]->params;
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
	
		xmlrpc_value *datastore = xmlrpc_build_value(envP, "{s:s,s:i,s:A}",
						"name", datastores[i]->name,
						"refcount", datastores[i]->refcount,
						"params", params);
	
		xmlrpc_array_append_item(envP, result, datastore);
		xmlrpc_DECREF(datastore);

	}

	datastore_unlock();

	return result;
}

xmlrpc_value *xmlrpccmd_list_avail_datastore(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	return xmlrpccmd_list_avail_modules(envP, "datastore");
	
}

xmlrpc_value *xmlrpccmd_get_datastore(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	main_config_datastores_lock(0);
	struct datastore *d = main_config->datastores;

	if (!d) {
		main_config_datastores_unlock();
		return xmlrpc_array_new(envP);
	}

	xmlrpc_value *datastores = xmlrpc_array_new(envP);

	while (d) {
		xmlrpc_value *params = xmlrpc_array_new(envP);

		datastore_lock_instance(d, 0);
		struct datastore_param *dp = d->params;
		while (dp) {
			char *value = ptype_print_val_alloc(dp->value);
			xmlrpc_value *param = xmlrpc_build_value(envP, "{s:s,s:s,s:s}",
						"name", dp->type->name,
						"value", value,
						"type", ptype_get_name(dp->value->type));
			free(value);
			xmlrpc_array_append_item(envP, params, param);
			xmlrpc_DECREF(param);
			dp = dp->next;
		}


		char *descr = "";
		if (d->description)
			descr = d->description;

		xmlrpc_value *datastore = xmlrpc_build_value(envP, "{s:s,s:s,s:b,s:i,s:i,s:s,s:A}", 
						"name", d->name,
						"type", datastore_get_name(d->type),
						"started", d->started,
						"uid", d->uid,
						"serial", d->serial,
						"description", descr,
						"params", params);
		xmlrpc_DECREF(params);

		xmlrpc_array_append_item(envP, datastores, datastore);
		xmlrpc_DECREF(datastore);

		datastore_unlock_instance(d);

		d = d->next;

	}
	main_config_datastores_unlock();

	return datastores;
}

xmlrpc_value *xmlrpccmd_add_datastore(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *datastore_type;
	char *datastore_name;

	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &datastore_type, &datastore_name);

	if (envP->fault_occurred)
		return NULL;

	char *tmp = datastore_name;
	if ((*tmp < 'a' && *tmp > 'z') && (*tmp < 'A' && *tmp > 'Z')) {
		xmlrpc_faultf(envP, "Invalid datastore name \"%s\", must start by a letter", datastore_name);
		free(datastore_name);
		free(datastore_type);
		return NULL;
	}

	tmp++;
	while (*tmp) {
		if ((*tmp < 'A' && *tmp > 'Z') && (*tmp < 'a' && *tmp > 'z') && (*tmp < '0' && *tmp > '9')) {
			xmlrpc_faultf(envP, "Invalid datastore name \"%s\", must be alphanumeric char only", datastore_name);
			free(datastore_name);
			free(datastore_type);
			return NULL;
		}
		tmp++;
	}

	main_config_datastores_lock(0);

	struct datastore *d = main_config->datastores;
	while (d) {
		if (!strcmp(d->name, datastore_name)) {
			main_config_datastores_unlock();
			xmlrpc_faultf(envP, "Datastore name \"%s\" is already used", datastore_name);
			free(datastore_name);
			free(datastore_type);
			return NULL;
		}
		d = d->next;
	}

	main_config_datastores_unlock();

	datastore_lock(1);

	int type = datastore_register(datastore_type);

	if (type == POM_ERR) {
		datastore_unlock();
		xmlrpc_faultf(envP, "Datastore type %s not found", datastore_name);
		free(datastore_name);
		free(datastore_type);
		return NULL;
	}

	d = datastore_alloc(type);
	datastore_unlock();
	free(datastore_type);

	if (!d) {
		main_config_datastores_unlock();
		xmlrpc_faultf(envP, "Error while allocating the datastore");
		free(datastore_name);
		return NULL;
	}

	main_config_datastores_lock(1);

	d->name = datastore_name;

	if (!main_config->datastores)
		main_config->datastores = d;
	else {
		struct datastore *tmpd = main_config->datastores;
		while (tmpd->next);
			tmpd = tmpd->next;

		tmpd->next = d;
		d->prev = tmpd;
	}

	main_config->datastores_serial++;
	main_config_datastores_unlock();

	return xmlrpc_int_new(envP, d->uid);
}

xmlrpc_value *xmlrpccmd_remove_datastore(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *datastore_name;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &datastore_name);

	if (envP->fault_occurred)
		return NULL;

	main_config_datastores_lock(1);
	struct datastore *d = mgmtcmd_get_datastore(datastore_name);
	free(datastore_name);

	if (!d) {
		main_config_datastores_unlock();
		xmlrpc_faultf(envP, "Datastore not found");
		return NULL;
	}

	datastore_lock_instance(d, 1);
	if (d->started)
		datastore_close(d);

	if (d->prev)
		d->prev->next = d->next;
	else
		main_config->datastores = d->next;

	if (d->next)
		d->next->prev = d->prev;

	datastore_cleanup(d);

	main_config_datastores_unlock();

	return xmlrpc_int_new(envP, 0);
}


xmlrpc_value *xmlrpccmd_start_datastore(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *datastore_name;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &datastore_name);

	if (envP->fault_occurred)
		return NULL;

	main_config_datastores_lock(0);
	struct datastore *d = mgmtcmd_get_datastore(datastore_name);
	free(datastore_name);

	if (!d) {
		main_config_datastores_unlock();
		xmlrpc_faultf(envP, "Datastore not found");
		return NULL;
	}

	datastore_lock_instance(d, 1);
	main_config_datastores_unlock();


	if (d->started) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Datastore already started");
		return NULL;
	}

	if (datastore_open(d) != POM_OK) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Error while starting the datastore");
		return NULL;
	}
	datastore_unlock_instance(d);

	return xmlrpc_int_new(envP, d->serial);
}


xmlrpc_value *xmlrpccmd_stop_datastore(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	char *datastore_name;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &datastore_name);

	if (envP->fault_occurred)
		return NULL;

	main_config_datastores_lock(0);
	struct datastore *d = mgmtcmd_get_datastore(datastore_name);
	free(datastore_name);

	if (!d) {
		main_config_datastores_unlock();
		xmlrpc_faultf(envP, "Datastore not found");
		return NULL;
	}

	datastore_lock_instance(d, 1);
	main_config_datastores_unlock();


	if (!d->started) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Datastore already stopped");
		return NULL;
	}

	if (datastore_close(d) != POM_OK) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Error while starting the datastore");
		return NULL;
	}
	datastore_unlock_instance(d);

	return xmlrpc_int_new(envP, d->serial);
}

xmlrpc_value *xmlrpccmd_set_datastore_parameter(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *ds_name, *param_name, *value;
	xmlrpc_decompose_value(envP, paramArrayP, "(sss)", &ds_name, &param_name, &value);

	if (envP->fault_occurred)
		return NULL;

	main_config_datastores_lock(0);
	
	struct datastore *d = mgmtcmd_get_datastore(ds_name);
	free(ds_name);
	
	if (!d) {
		main_config_datastores_unlock();
		xmlrpc_faultf(envP, "Datastore not found");
		free(param_name);
		free(value);
		return NULL;
	}

	datastore_lock_instance(d,1);
	main_config_datastores_unlock();

	if (d->started) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Datastore must be stopped to change a parameter");
		free(param_name);
		free(value);
		return NULL;
	}

	struct ptype *v = datastore_get_param_value(d, param_name);

	if (!v) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "The parameter %s does not exists", param_name);
		free(param_name);
		free(value);
		return NULL;
	}
	free(param_name);

	if (ptype_parse_val(v, value) == POM_ERR) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Unable to parse the value \"%s\"", value);
		free(value);
		return NULL;
	}

	main_config->datastores_serial++;
	d->serial++;
	uint32_t serial = d->serial;
	datastore_unlock_instance(d);

	free(value);

	return xmlrpc_int_new(envP, serial);

}

xmlrpc_value *xmlrpccmd_set_datastore_description(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *ds_name, *descr;
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &ds_name, &descr);

	if (envP->fault_occurred)
		return NULL;

	main_config_datastores_lock(0);
	
	struct datastore *d = mgmtcmd_get_datastore(ds_name);
	free(ds_name);
	
	if (!d) {
		main_config_datastores_unlock();
		xmlrpc_faultf(envP, "Datastore not found");
		free(descr);
		return NULL;
	}

	datastore_lock_instance(d, 1);
	main_config_datastores_unlock();


	if (d->description)
		free(d->description);

	if (strlen(descr)) {
		d->description = descr;
	} else {
		d->description = NULL;
		free(descr);
	}

	main_config->datastores_serial++;
	d->serial++;
	uint32_t serial = d->serial;
	datastore_unlock_instance(d);

	return xmlrpc_int_new(envP, serial);
}

xmlrpc_value *xmlrpccmd_load_datastore(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	datastore_lock(1);
	
	if (datastore_get_type(name) != POM_ERR) {
		datastore_unlock();
		xmlrpc_faultf(envP, "Datastore %s already registered", name);
		free(name);
		return NULL;
	}

	int id = datastore_register(name);
	datastore_unlock();
	free(name);
	
	if (id == POM_ERR) {
		xmlrpc_faultf(envP, "Error while loading datastore");
		return NULL;
	}

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_unload_datastore(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	datastore_lock(1);
	int id = datastore_get_type(name);

	xmlrpc_value *res = NULL;
	
	if (id == POM_ERR) {
		xmlrpc_faultf(envP, "Datastore %s not loaded yet", name);
	} else if (datastores[id]->refcount) {
		xmlrpc_faultf(envP, "Datastore %s is still in use. Cannot unload it", name);
	} else if (datastore_unregister(id) == POM_OK) {
		res = xmlrpc_int_new(envP, 0);
	} else {
		xmlrpc_faultf(envP, "Error while unload datastore %s", name);
	}

	datastore_unlock();
	free(name);

	return res;
}

xmlrpc_value *xmlrpccmd_datastore_list_dataset(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &name);

	if (envP->fault_occurred)
		return NULL;

	main_config_datastores_lock(0);
	
	struct datastore *d = mgmtcmd_get_datastore(name);
	free(name);

	if (!d) {
		main_config_datastores_unlock();
		xmlrpc_faultf(envP, "Datastore not found");
		return NULL;
	}

	main_config_datastores_unlock();
	datastore_lock_instance(d, 0);

	if (!d->started) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Datastore needs to be started to list the datasets");
		return NULL;
	}

	xmlrpc_value *result = xmlrpc_array_new(envP);

	struct dataset *ds = d->datasets;
	while (ds) {
		xmlrpc_value *dset = xmlrpc_build_value(envP, "{s:s,s:s,s:s}",
					"name", ds->name,
					"type", ds->type,
					"descr", ds->descr);
		xmlrpc_array_append_item(envP, result, dset);
		xmlrpc_DECREF(dset);

		ds = ds->next;
	}
	datastore_unlock_instance(d);

	return result;
}

xmlrpc_value *xmlrpccmd_datastore_destroy_dataset(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *name, *dset_name;
	xmlrpc_decompose_value(envP, paramArrayP, "(ss)", &name, &dset_name);

	if (envP->fault_occurred)
		return NULL;

	main_config_datastores_lock(0);
	
	struct datastore *d = mgmtcmd_get_datastore(name);
	free(name);

	if (!d) {
		main_config_datastores_unlock();
		xmlrpc_faultf(envP, "Datastore not found");
		free(dset_name);
		return NULL;
	}

	main_config_datastores_unlock();
	datastore_lock_instance(d, 1);

	if (!d->started) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Datastore needs to be started to list the datasets");
		free(dset_name);
		return NULL;
	}

	struct dataset *ds = d->datasets;
	while (ds && strcmp(ds->name, dset_name))
		ds = ds->next;

	if (!ds) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Dataset %s not found", dset_name);
		free(dset_name);
		return NULL;
	}

	free(dset_name);

	if (datastore_dataset_destroy(ds) == POM_ERR) {
		datastore_unlock_instance(d);
		xmlrpc_faultf(envP, "Error while destroying the dataset");
		return NULL;
	}

	datastore_unlock_instance(d);

	return xmlrpc_int_new(envP, 0);
}
