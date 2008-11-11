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



#include "mgmtcmd_datastore.h"
#include "datastore.h"


#define MGMT_DATASTORE_COMMANDS_NUM 10

static struct mgmt_command mgmt_datastore_commands[MGMT_DATASTORE_COMMANDS_NUM] = {

	{
		.words = { "show", "datastores", NULL },
		.help = "Display informations about the datastores in every datastore",
		.callback_func = mgmtcmd_show_datastores,
	},

	{
		.words = { "start", "datastore", NULL },
		.help = "Start a datastore",
		.callback_func = mgmtcmd_start_datastore,
		.usage = "start datastore <datastore_name>",
		.completion = mgmtcmd_datastore_completion_name2,
	},

	{
		.words = { "stop", "datastore", NULL },
		.help = "Stop a datastore",
		.callback_func = mgmtcmd_stop_datastore,
		.usage = "stop datastore <datastore_name>",
		.completion = mgmtcmd_datastore_completion_name2,
	},

	{
		.words = { "add", "datastore", NULL },
		.help = "Add a datastore to a datastore",
		.callback_func = mgmtcmd_add_datastore,
		.usage = "add datastore <datastore> <datastore_name>",
		.completion = mgmtcmd_datastore_type_completion,
	},

	{
		.words = { "remove", "datastore", NULL },
		.help = "Remove a datastore from a datastore",
		.callback_func = mgmtcmd_remove_datastore,
		.usage = "remove datastore <datastore_name>",
		.completion = mgmtcmd_datastore_completion_name2,
	},

	{
		.words = { "set", "datastore", "parameter", NULL },
		.help = "Change the value of a datastore parameter",
		.callback_func = mgmtcmd_set_datastore_parameter,
		.usage = "set datastore parameter <datastore_name> <parameter> <value>",
		.completion = mgmtcmd_set_datastore_parameter_completion,
	},

	{
		.words = { "set", "datastore", "description",  NULL },
		.help = "set a description on a datastore",
		.callback_func = mgmtcmd_set_datastore_descr,
		.completion = mgmtcmd_datastore_completion_name3,
		.usage = "set datastore description <datastore_id> <descr>",
	},

	{
		.words = { "unset", "datastore", "description", NULL },
		.help = "unset the description of a datastore",
		.callback_func = mgmtcmd_unset_datastore_descr,
		.completion = mgmtcmd_datastore_completion_name3,
		.usage = "unset datastore description <datastore_name>",
	},

	{
		.words = { "load", "datastore", NULL },
		.help = "Load a datastore into the system",
		.usage = "load datastore <datastore>",
		.callback_func = mgmtcmd_load_datastore,
		.completion = mgmtcmd_load_datastore_completion,
	},

	{
		.words = { "unload", "datastore", NULL },
		.help = "Unload a datastore from the system",
		.usage = "unload datastore <datastore>",
		.callback_func = mgmtcmd_unload_datastore,
		.completion = mgmtcmd_unload_datastore_completion,
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
int mgmtcmd_show_datastores(struct mgmt_connection *c, int argc, char *argv[]) {

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
			mgmtsrv_send(c, "        %s = %s %s\r\n", p->type->name, buff, p->value->unit);
			p = p->next;
		}
		mgmtsrv_send(c, "\r\n");

		d = d->next;
	}

	main_config_datastores_unlock();

	return POM_OK;
}

int mgmtcmd_start_datastore(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;


	struct datastore *d = mgmtcmd_get_datastore(argv[0]);

	if (!d) {
		mgmtsrv_send(c, "Datastore not found\r\n");
		return POM_OK;
	}

	datastore_lock_instance(d, 0);
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

int mgmtcmd_stop_datastore(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;

	main_config_datastores_lock(0);

	struct datastore *d = mgmtcmd_get_datastore(argv[0]);

	main_config_datastores_unlock();

	if (!d) {
		mgmtsrv_send(c, "Datastore not found\r\n");
		return POM_OK;
	}
	
	datastore_lock_instance(d, 0);
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

int mgmtcmd_add_datastore(struct mgmt_connection *c, int argc, char *argv[]) {
	
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
		mgmtsrv_send(c, "Datastore %s not found\r\n", argv[1]);
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

int mgmtcmd_remove_datastore(struct mgmt_connection *c, int argc, char *argv[]) {
	
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

int mgmtcmd_set_datastore_parameter(struct mgmt_connection *c, int argc, char *argv[]) {
	
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

struct mgmt_command_arg *mgmtcmd_set_datastore_parameter_completion(int argc, char *argv[]) {

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

int mgmtcmd_set_datastore_descr(struct mgmt_connection *c, int argc, char *argv[]) {
	
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

int mgmtcmd_unset_datastore_descr(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;

	main_config_datastores_lock(0);

	struct datastore *d = mgmtcmd_get_datastore(argv[0]);

	if (!d) {
		datastore_unlock();
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

int mgmtcmd_load_datastore(struct mgmt_connection *c, int argc, char*argv[]) {

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

struct mgmt_command_arg* mgmtcmd_load_datastore_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("datastore");
	return res;
}

int mgmtcmd_unload_datastore(struct mgmt_connection *c, int argc, char *argv[]) {


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

struct mgmt_command_arg* mgmtcmd_unload_datastore_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc != 2)
		return NULL;

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

	return res;
}
