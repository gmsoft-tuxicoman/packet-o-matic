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


#include "mgmtcmd_helper.h"


#define MGMT_HELPER_COMMANDS_NUM 4

struct mgmt_command mgmt_helper_commands[MGMT_HELPER_COMMANDS_NUM] = {

	{
		.words = { "show", "helpers", NULL },
		.help = "Display information about the loaded helpers",
		.callback_func = mgmtcmd_show_helpers,
	},

	{
		.words = { "load", "helper", NULL },
		.help = "Load an helper into the system",
		.usage = "load helper <helper_name>",
		.callback_func = mgmtcmd_load_helper,
	},

	{
		.words = { "set", "helper", "parameter", NULL},
		.help = "Change the value of a helper parameter",
		.usage = "set helper parameter <helper> <parameter> <value>",
		.callback_func = mgmtcmd_set_helper_param,
	},

	{
		.words = { "unload", "helper", NULL },
		.help = "Unload an helper from the system",
		.usage = "unload helper <helper>",
		.callback_func = mgmtcmd_unload_helper,
	},

};

int mgmtcmd_helper_register_all() {

	int i;


	for (i = 0; i < MGMT_HELPER_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_helper_commands[i]);
	}

	return POM_OK;
}


int mgmtcmd_show_helpers(struct mgmt_connection *c, int argc, char *argv[]) {

	mgmtsrv_send(c, "Loaded helpers : \r\n");


	int i;
	for (i = 0; i < MAX_HELPER; i++) {
		if (!helpers[i])
			continue;
		mgmtsrv_send(c, "  %s\r\n", match_get_name(i));

		struct helper_param *tmp = helpers[i]->params;
		while (tmp) {
			char buff[256];
			bzero(buff, sizeof(buff));
			ptype_print_val(tmp->value, buff, sizeof(buff));

			mgmtsrv_send(c, "   %s = %s %s\r\n", tmp->name, buff, tmp->value->unit);
			tmp = tmp->next;
		}
	}
				

	return POM_OK;
}



int mgmtcmd_load_helper(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Cannot load helper %s : corresponding match not loaded yet\r\n", argv[0]);
		return POM_OK;
	}

	if (helpers[id]) {
		mgmtsrv_send(c, "Helper %s already loaded\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock();
	if (helper_register(argv[0]) != POM_ERR) {
		mgmtsrv_send(c, "Helper %s registered successfully\r\n", argv[0]);
	} else {
		mgmtsrv_send(c, "Error while loading helper %s\r\n", argv[0]);
	}
	reader_process_unlock();
	
	return POM_OK;

}


int mgmtcmd_set_helper_param(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc != 3) 
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);
	if (!helpers[id]) {
		mgmtsrv_send(c, "No helper with that name loaded\r\n");
		return POM_OK;
	}

	struct helper_param *p = helper_get_param(id, argv[1]);
	if (!p) {
		mgmtsrv_send(c, "This parameter does not exists\r\n");
		return POM_OK;
	}

	if (ptype_parse_val(p->value, argv[2]) != POM_OK) {
		mgmtsrv_send(c, "Invalid value given\r\n");
		return POM_OK;
	}

	return POM_OK;

}

int mgmtcmd_unload_helper(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (id == POM_ERR || !helpers[id]) {
		mgmtsrv_send(c, "Helper not loaded\r\n");
		return POM_OK;
	}

	reader_process_lock();
	if (helper_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Helper unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading helper\r\n");
	}
	reader_process_unlock();
	
	return POM_OK;

}
