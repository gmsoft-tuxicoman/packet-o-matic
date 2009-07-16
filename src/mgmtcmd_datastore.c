/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2009 Guy Martin <gmsoft@tuxicoman.be>
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



#include "mgmtcmd_datastore.h"
#include "datastore.h"


#define MGMT_DATASTORE_COMMANDS_NUM 13

static struct mgmt_command mgmt_datastore_commands[MGMT_DATASTORE_COMMANDS_NUM] = {

	{
		.words = { "datastore", "show", NULL },
		.help = "Display informations about the datastores in every datastore",
		.callback_func = mgmtcmd_datastore_show,
	},

	{
		.words = { "datastore", "start", NULL },
		.help = "Start a datastore",
		.callback_func = mgmtcmd_datastore_start,
		.usage = "datastore start <name>",
		.completion = mgmtcmd_datastore_completion_name2,
	},

	{
		.words = { "datastore", "stop", NULL },
		.help = "Stop a datastore",
		.callback_func = mgmtcmd_datastore_stop,
		.usage = "datastore stop <name>",
		.completion = mgmtcmd_datastore_completion_name2,
	},

	{
		.words = { "datastore", "add", NULL },
		.help = "Add a datastore to a datastore",
		.callback_func = mgmtcmd_datastore_add,
		.usage = "datastore add <datastore_type> <datastore_name>",
		.completion = mgmtcmd_datastore_type_completion,
	},

	{
		.words = { "datastore", "remove", NULL },
		.help = "Remove a datastore from a datastore",
		.callback_func = mgmtcmd_datastore_remove,
		.usage = "datastore remove <datastore_name>",
		.completion = mgmtcmd_datastore_completion_name2,
	},

	{
		.words = { "datastore", "parameter", "set", NULL },
		.help = "Change the value of a datastore parameter",
		.callback_func = mgmtcmd_datastore_parameter_set,
		.usage = "datastore parameter set <datastore_name> <parameter> <value>",
		.completion = mgmtcmd_datastore_parameter_set_completion,
	},

	{
		.words = { "datastore", "description", "set", NULL },
		.help = "Set a description on a datastore",
		.callback_func = mgmtcmd_datastore_description_set,
		.completion = mgmtcmd_datastore_completion_name3,
		.usage = "datastore description set <datastore_name> <descr>",
	},

	{
		.words = { "datastore", "description", "unset", NULL },
		.help = "Unset the description of a datastore",
		.callback_func = mgmtcmd_datastore_description_unset,
		.completion = mgmtcmd_datastore_completion_name3,
		.usage = "datastore description unset <datastore_name>",
	},

	{
		.words = { "datastore", "load", NULL },
		.help = "Load a datastore module",
		.usage = "datastore load <datastore_type>",
		.callback_func = mgmtcmd_datastore_load,
		.completion = mgmtcmd_datastore_avail_completion,
	},

	{
		.words = { "datastore", "help", NULL },
		.help = "Get help for datastores",
		.usage = "datastore help [datastore_type]",
		.callback_func = mgmtcmd_datastore_help,
		.completion = mgmtcmd_datastore_avail_completion,
	},

	{
		.words = { "datastore", "unload", NULL },
		.help = "Unload a datastore module",
		.usage = "datastore unload <datastore_type>",
		.callback_func = mgmtcmd_datastore_unload,
		.completion = mgmtcmd_datastore_unload_completion,
	},

	{
		.words = { "datastore", "dataset", "show", NULL },
		.help = "Shows the datasets of datastores",
		.usage = "datastore dataset show [datastore_name]",
		.callback_func = mgmtcmd_datastore_dataset_show,
		.completion = mgmtcmd_datastore_completion_name3,
	},

	{
		.words = { "datastore", "dataset", "destroy", NULL },
		.help = "Destroy a dataset",
		.usage = "datastore dataset destroy <datastore_name> <dataset>",
		.callback_func = mgmtcmd_datastore_dataset_destroy,
		.completion = mgmtcmd_datastore_dataset_destroy_completion,
	},
};

int mgmtcmd_datastore_register_all() {

	int i;

	for (i = 0; i < MGMT_DATASTORE_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_datastore_commands[i]);
	}

	return POM_OK;
}

struct mgmt_command_arg *mgmctcmd_datastore_name_completion(int argc, char *argv[], int pos) {

	struct mgmt_command_arg *res = NULL;

	main_config_datastores_lock(0);
	struct datastore *d = main_config->datastores;
	for (d = main_config->datastores; d; d = d->next) {
		struct mgmt_command_arg* item = malloc(sizeof(struct mgmt_command_arg));
		memset(item, 0, sizeof(struct mgmt_command_arg));
		item->word = malloc(strlen(d->name) + 1);
		strcpy(item->word, d->name);
		item->next = res;
		res = item;

	}
	main_config_datastores_unlock();


	return res;
}

struct mgmt_command_arg *mgmtcmd_datastore_completion_name2(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	return mgmctcmd_datastore_name_completion(argc, argv, argc - 2);

}

struct mgmt_command_arg *mgmtcmd_datastore_completion_name3(int argc, char *argv[]) {

	if (argc != 3)
		return NULL;

	return mgmctcmd_datastore_name_completion(argc, argv, argc - 3);

}
int mgmtcmd_datastore_show(struct mgmt_connection *c, int argc, char *argv[]) {

	main_config_datastores_lock(0);
	struct datastore *d = main_config->datastores;

	if (!d) {
		mgmtsrv_send(c, "No datastore configured\r\n");
		main_config_datastores_unlock();
		return POM_OK;
	}

	while (d) {
		
		mgmtsrv_send(c, "Datastore %s of type %s", d->name, datastore_get_name(d->type));
		if (d->started)
			mgmtsrv_send(c, " (running)");
		else
			mgmtsrv_send(c, " (stopped)");
		if (d->description)
			mgmtsrv_send(c, " // %s", d->description);
		mgmtsrv_send(c, "\r\n");

		struct datastore_param *p = d->params;
		while (p) {
			char buff[256];
			memset(buff, 0, sizeof(buff));
			ptype_print_val(p->value , buff, sizeof(buff));
			mgmtsrv_send(c, "   %s = %s %s\r\n", p->type->name, buff, p->value->unit);
			p = p->next;
		}
		mgmtsrv_send(c, "\r\n");

		d = d->next;
	}

	main_config_datastores_unlock();

	return POM_OK;
}

int mgmtcmd_datastore_start(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;

	main_config_datastores_lock(0);
	struct datastore *d = mgmtcmd_get_datastore(argv[0]);

	if (!d) {
		mgmtsrv_send(c, "Datastore not found\r\n");
		main_config_datastores_unlock();
		return POM_OK;
	}

	datastore_lock_instance(d, 1);
	main_config_datastores_unlock();

	if (d->started) {
		datastore_unlock_instance(d);
		mgmtsrv_send(c, "Datastore already started\r\n");
		return POM_OK;
	}

	if (datastore_open(d) != POM_OK) 
		mgmtsrv_send(c, "Error while starting the datastore\r\n");
	
	datastore_unlock_instance(d);

	return POM_OK;

}

int mgmtcmd_datastore_stop(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;

	main_config_datastores_lock(0);

	struct datastore *d = mgmtcmd_get_datastore(argv[0]);

	if (!d) {
		main_config_datastores_unlock();
		mgmtsrv_send(c, "Datastore not found\r\n");
		return POM_OK;
	}

	datastore_lock_instance(d, 0);
	main_config_datastores_unlock();

	if (!d->started) {
		datastore_unlock_instance(d);
		mgmtsrv_send(c, "Datastore already stopped\r\n");
		return POM_OK;
	}

	if (datastore_close(d) != POM_OK)
		mgmtsrv_send(c, "Error while stopping the datastore\r\n");
	
	datastore_unlock_instance(d);

	return POM_OK;

}

int mgmtcmd_datastore_add(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	// Verify name
	char *tmp = argv[1];
	if ((*tmp < 'a' && *tmp > 'z') && (*tmp < 'A' && *tmp > 'Z')) {
		mgmtsrv_send(c, "Invalid datastore name \"%s\", must start by a letter", argv[1]);
		return POM_OK;
	}
	tmp++;
	while (*tmp) {
		if ((*tmp < 'A' && *tmp > 'Z') && (*tmp < 'a' && *tmp > 'z') && (*tmp < '0' && *tmp > '9')) {
			mgmtsrv_send(c, "Invalid datastore name \"%s\", must be alphanumeric char only", argv[1]);
			return POM_OK;
		}
		tmp++;
	}

	main_config_datastores_lock(0);
	struct datastore *d = main_config->datastores;
	while (d) {
		if (!strcmp(d->name, argv[1])) {
			mgmtsrv_send(c, "Datastore name \"%s\" is already used\r\n", argv[1]);
			main_config_datastores_unlock();
			return POM_OK;
		}
		d = d->next;
	}

	main_config_datastores_unlock();

	datastore_lock(1);
	int datastore_type = datastore_register(argv[0]);

	if (datastore_type == POM_ERR) {
		datastore_unlock();
		mgmtsrv_send(c, "Datastore type %s not found\r\n", argv[0]);
		return POM_OK;
	}
	
	main_config_datastores_lock(1);
	d = datastore_alloc(datastore_type);
	datastore_unlock();
	if (!d) {
		main_config_datastores_unlock();
		mgmtsrv_send(c, "Error while allocating the datastore !!!\r\n");
		return POM_ERR;
	}

	d->name = malloc(strlen(argv[1]) + 1);
	strcpy(d->name, argv[1]);

	// add the datastore at the end
	if (!main_config->datastores) 
		main_config->datastores = d;
	else {
		struct datastore *tmpd = main_config->datastores;
		while (tmpd->next) {
			tmpd = tmpd->next;
		}
		tmpd->next = d;
		d->prev = tmpd;
	}

	main_config->datastores_serial++;
	main_config_datastores_unlock();

	mgmtsrv_send(c, "Datastore \"%s\" added (type %s)\r\n", argv[1], argv[0]);

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_datastore_type_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;

	res = mgmtcmd_list_modules("datastore");
	return res;
}

struct datastore *mgmtcmd_get_datastore(char *datastore) {

	struct datastore *d = main_config->datastores;

	while (d) {
		if (!strcmp(d->name, datastore)) 
			return d;

		d = d->next;
	}

	return NULL;

}

int mgmtcmd_datastore_remove(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;

	main_config_datastores_lock(1);
	struct datastore *d = mgmtcmd_get_datastore(argv[0]);

	if (!d) {
		main_config_datastores_unlock();
		mgmtsrv_send(c, "Datastore not found\r\n");
		return POM_OK;
	}

	if (d->started) {
		datastore_close(d);
	}

	main_config->datastores_serial++;

	if (d->prev)
		d->prev->next = d->next;
	else
		main_config->datastores = d->next;
	
	if (d->next)
		d->next->prev = d->prev;

	datastore_cleanup(d);

	main_config_datastores_unlock();

	mgmtsrv_send(c, "Datastore removed\r\n");

	return POM_OK;

}

int mgmtcmd_datastore_parameter_set(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	main_config_datastores_lock(0);

	struct datastore *d = mgmtcmd_get_datastore(argv[0]);


	if (!d) {
		main_config_datastores_unlock();
		mgmtsrv_send(c, "Datastore not found\r\n");
		return POM_OK;
	}

	datastore_lock_instance(d, 1);
	main_config_datastores_unlock();

	if (d->started) {
		datastore_unlock_instance(d);
		mgmtsrv_send(c, "Datastore must be stopped to change a parameter\r\n");
		return POM_OK;
	}
	

	struct ptype *value = datastore_get_param_value(d, argv[1]);
	if (!value) {
		datastore_unlock_instance(d);
		mgmtsrv_send(c, "No parameter %s for datastore %s\r\n", argv[1], datastore_get_name(d->type));
		return POM_OK;
	}

	if (ptype_parse_val(value, argv[2]) == POM_ERR) {
		datastore_unlock_instance(d);
		mgmtsrv_send(c, "Unable to parse \"%s\" for parameter %s\r\n", argv[2], argv[1]);
		return POM_OK;
	}

	main_config->datastores_serial++;
	d->serial++;
	datastore_unlock_instance(d);

	return POM_OK;

}

struct mgmt_command_arg *mgmtcmd_datastore_parameter_set_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc == 3) {

		res = mgmctcmd_datastore_name_completion(argc, argv, argc - 3);

	} else if (argc == 4) {

		main_config_datastores_lock(0);

		struct datastore *d = main_config->datastores;

		while (d) {
			if (!strcmp(d->name, argv[argc - 1]))
				break;
			d = d->next;
		}
		
		if (!d) {
			main_config_datastores_unlock();
			return NULL;
		}

		struct datastore_param_reg *p = datastores[d->type]->params;

		while (p) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			char *name = p->name;
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;

			p = p->next;
		}

		main_config_datastores_unlock();

	}
	return res;
}

int mgmtcmd_datastore_description_set(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	main_config_datastores_lock(0);

	struct datastore *d = mgmtcmd_get_datastore(argv[0]);


	if (!d) {
		main_config_datastores_unlock();
		mgmtsrv_send(c, "Datastore not found\r\n");
		return POM_OK;
	}

	datastore_lock_instance(d, 1);
	main_config_datastores_unlock();

	if (d->description)
		free(d->description);

	// first, let's reconstruct the whole description
	int datastore_descr_len = 0, i;
	for (i = 2; i < argc; i++) {
		datastore_descr_len += strlen(argv[i]) + 1;
	}
	char *datastore_descr = malloc(datastore_descr_len + 1);
	memset(datastore_descr, 0, datastore_descr_len + 1);
	for (i = 1; i < argc; i++) {
		strcat(datastore_descr, argv[i]);
		strcat(datastore_descr, " ");
	}
	datastore_descr[strlen(datastore_descr) - 1] = 0;
	d->description = datastore_descr;

	main_config->datastores_serial++;
	d->serial++;
	datastore_unlock_instance(d);

	return POM_OK;

}

int mgmtcmd_datastore_description_unset(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;

	main_config_datastores_lock(0);

	struct datastore *d = mgmtcmd_get_datastore(argv[0]);

	if (!d) {
		main_config_datastores_unlock();
		mgmtsrv_send(c, "Datastore not found\r\n");
		return POM_OK;
	}

	datastore_lock_instance(d, 1);
	main_config_datastores_unlock();

	if (d->description) {
		free(d->description);
		d->description = NULL;
		main_config->datastores_serial++;
		d->serial++;
	} else {
		mgmtsrv_send(c, "Datastore %s has no description\r\n", argv[0]);
	}

	datastore_unlock_instance(d);

	return POM_OK;

}

int mgmtcmd_datastore_load(struct mgmt_connection *c, int argc, char*argv[]) {

	if (argc != 1)
		return MGMT_USAGE;
	datastore_lock(1);	
	if (datastore_get_type(argv[0]) != POM_ERR) {
		datastore_unlock();
		mgmtsrv_send(c, "Datastore %s is already registered\r\n", argv[0]);
		return POM_OK;
	}

	int id = datastore_register(argv[0]);
	datastore_unlock();
	if (id == POM_ERR)
		mgmtsrv_send(c, "Error while loading datastore %s\r\n", argv[0]);
	else
		mgmtsrv_send(c, "Datastore %s regitered with id %u\r\n", argv[0], id);

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_datastore_avail_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("datastore");
	return res;
}

int mgmtcmd_datastore_help(struct mgmt_connection *c, int argc, char *argv[]) {

	int single = 0, id = 0, displayed = 0;
	if (argc >= 1) {
		single = 1;
		datastore_lock(1);
		id = datastore_register(argv[0]);
		datastore_unlock();
		if (id == POM_ERR) {
			mgmtsrv_send(c, "Non exisiting datastore %s\r\n", argv[0]);
			return POM_OK;
		}
	}

	datastore_lock(0);
	for (; id < MAX_DATASTORE; id++) {
		char *name = datastore_get_name(id);
		if (!name)
			continue;

		displayed++;

		mgmtsrv_send(c, "Datastore %s :\r\n", name);

		struct datastore_param_reg *dp = datastores[id]->params;
		if (!dp) {
			mgmtsrv_send(c, "  no parameter for this datastore\r\n");
		} else {
			while (dp) {
				mgmtsrv_send(c, "  %s : %s (default : '%s')\r\n", dp->name, dp->descr, dp->defval);
				dp = dp->next;
			}
		}

		mgmtsrv_send(c, "\r\n");

		if (single)
			break;
	}

	datastore_unlock();

	if (!displayed)
		mgmtsrv_send(c, "No datastore loaded\r\n");

	return POM_OK;
}

int mgmtcmd_datastore_unload(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;
	
	datastore_lock(1);
	int id = datastore_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Datastore %s not loaded\r\n", argv[0]);
	} else if (datastores[id]->refcount) {
		mgmtsrv_send(c, "Datastore %s is still in use. Cannot unload it\r\n", argv[0]);
	} else if (datastore_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Datastore %s unloaded successfully\r\n", argv[0]);
	} else {
		mgmtsrv_send(c, "Error while unloading datastore %s\r\n", argv[0]);
	}

	datastore_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_datastore_unload_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc != 2)
		return NULL;

	datastore_lock(0);

	int i;
	for (i = 0; i < MAX_DATASTORE; i++) {
		if (datastores[i]) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			char *name = datastores[i]->name;
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;
		}

	}

	datastore_unlock();

	return res;
}

int mgmtcmd_datastore_dataset_show(struct mgmt_connection *c, int argc, char *argv[]) {

	int single = 0;
	struct datastore *d;

	if (argc == 1)
		single = 1;
	else if (argc > 1)
		return MGMT_USAGE;


	main_config_datastores_lock(0);

	if (single)
		d = mgmtcmd_get_datastore(argv[0]);
	else
		d = main_config->datastores;

	while (d) {
		datastore_lock_instance(d, 0);

		mgmtsrv_send(c, "Datasets in datastore %s (%s) :\r\n", d->name, datastores[d->type]->name);
		
		struct dataset *ds = d->datasets;
		if (!d->started) {
			mgmtsrv_send(c, "  cannot show datasets because the datastore is stopped\r\n");
		} else if (!ds) {
			mgmtsrv_send(c, "  no dataset in this datastore\r\n");
		} else {
			while (ds) {
				
				mgmtsrv_send(c, "  %s (%s) : %s\r\n", ds->name, ds->type, ds->descr);
				ds = ds->next;
			}
		}

		datastore_unlock_instance(d);

		mgmtsrv_send(c, "\r\n");

		if (single)
			break;

		d = d->next;

	}
	main_config_datastores_unlock();

	return POM_OK;
}

int mgmtcmd_datastore_dataset_destroy(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc != 2)
		return MGMT_USAGE;

	main_config_datastores_lock(0);

	struct datastore *d = mgmtcmd_get_datastore(argv[0]);

	if (!d) {
		main_config_datastores_unlock();
		mgmtsrv_send(c, "Datastore not found\r\n");
		return POM_OK;
	}

	datastore_lock_instance(d, 1);
	main_config_datastores_unlock();

	struct dataset *ds = d->datasets;
	while (ds && strcmp(ds->name, argv[1]))
		ds = ds->next;
	if (!ds) {
		datastore_unlock_instance(d);
		mgmtsrv_send(c, "Dataset not found in datastore %s\r\n", d->name);
		return POM_OK;

	}

	if (datastore_dataset_destroy(ds) == POM_ERR)
		mgmtsrv_send(c, "Error while destroying the dataset\r\n");

	datastore_unlock_instance(d);
	return POM_OK;
}

struct mgmt_command_arg *mgmtcmd_datastore_dataset_destroy_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc == 3) {

		res = mgmctcmd_datastore_name_completion(argc, argv, argc - 3);

	} else if (argc == 4) {

		main_config_datastores_lock(0);

		struct datastore *d = main_config->datastores;

		while (d) {
			if (!strcmp(d->name, argv[argc - 1]))
				break;
			d = d->next;
		}
		
		if (!d) {
			main_config_datastores_unlock();
			return NULL;
		}

		datastore_lock_instance(d, 0);
		main_config_datastores_unlock();

		struct dataset *ds = d->datasets;

		while (ds) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			char *name = ds->name;
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;

			ds = ds->next;
		}

		datastore_unlock_instance(d);


	}
	return res;
}
