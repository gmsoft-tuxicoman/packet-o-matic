/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007 Guy Martin <gmsoft@tuxicoman.be>
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
#include "mgmtsrv.h"
#include "mgmtcmd.h"
#include "helper.h"
#include "match.h"
#include "ptype.h"

extern struct helper_reg *helpers[];


#define MGMT_COMMANDS_NUM 5

struct mgmt_command mgmt_commands[MGMT_COMMANDS_NUM] = {

	{
		.words = { "exit", NULL },
		.help = "Exit the management console",
		.callback_func = mgmtcmd_exit,
	},

	{
		.words = { "show", "license", NULL },
		.help = "Display the license of this program",
		.callback_func = mgmtcmd_show_license,
	},

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
		.usage = "set helper parameter <helper> <parameter_name> <parameter value>",
		.callback_func = mgmtcmd_set_helper_param,
	},
};

int mgmtcmd_register_all() {

	int i;


	for (i = 0; i < MGMT_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_commands[i]);
	}

	return MGMT_OK;
}


int mgmtcmd_exit(struct mgmt_connection *c, int argc, char *argv[]) {
	
	char *bye_msg = "\r\nThanks for using packet-o-matic ! Bye !\r\n";
	mgmtsrv_send(c, bye_msg);
	mgmtsrv_close_connection(c);

	return MGMT_OK;

}



int mgmtcmd_show_license(struct mgmt_connection *c, int argc, char *argv[]) {

	char *license_msg = 
		"This program is free software; you can redistribute it and/or modify\r\n" 
		"it under the terms of the GNU General Public License as published by\r\n"
		"the Free Software Foundation; either version 2 of the License, or\r\n"
		"(at your option) any later version.\r\n"
		"\r\n"
		"This program is distributed in the hope that it will be useful,\r\n"
		"but WITHOUT ANY WARRANTY; without even the implied warranty of\r\n"
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\r\n"
		"GNU General Public License for more details.\r\n"
		"\r\n"
		"You should have received a copy of the GNU General Public License\r\n"
		"along with this program; if not, write to the Free Software\r\n"
		"Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA\r\n";
	
	mgmtsrv_send(c, license_msg);
	return MGMT_OK;
}

int mgmtcmd_show_helpers(struct mgmt_connection *c, int argc, char *argv[]) {

	mgmtsrv_send(c, "Loaded helpers : \r\n");


	int i;
	for (i = 0; i < MAX_HELPER; i++) {
		if (!helpers[i])
			continue;
		mgmtsrv_send(c, "    ");
		mgmtsrv_send(c, match_get_name(i));
		mgmtsrv_send(c, "\r\n");

		struct helper_param *tmp = helpers[i]->params;
		while (tmp) {
			mgmtsrv_send(c, "        ");
			mgmtsrv_send(c, tmp->name);
			mgmtsrv_send(c, " = ");

			char buff[256];
			bzero(buff, sizeof(buff));
			ptype_print_val(tmp->value, buff, 256);
			mgmtsrv_send(c, buff);
			mgmtsrv_send(c, " ");
			mgmtsrv_send(c, tmp->value->unit);
			mgmtsrv_send(c, "\r\n");

			tmp = tmp->next;
		}
	}
				

	return MGMT_OK;
}



int mgmtcmd_load_helper(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (id == -1) {
		mgmtsrv_send(c, "Cannot load helper : corresponding match not loaded yet\r\n");
		return MGMT_OK;
	}

	if (helpers[id]) {
		mgmtsrv_send(c, "Helper already loaded\r\n");
		return MGMT_OK;
	}

	if (helper_register(argv[0]) != H_ERR) {
		mgmtsrv_send(c, "Helper registered successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while loading helper\r\n");
	}
	
	return MGMT_OK;

}


int mgmtcmd_set_helper_param(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc != 3) 
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);
	if (!helpers[id]) {
		mgmtsrv_send(c, "No helper with that name loaded\r\n");
		return MGMT_OK;
	}

	struct helper_param *p = helper_get_param(id, argv[1]);
	if (!p) {
		mgmtsrv_send(c, "This parameter does not exists\r\n");
		return MGMT_OK;
	}

	if (ptype_parse_val(p->value, argv[2]) != P_OK) {
		mgmtsrv_send(c, "Invalid value given\r\n");
		return MGMT_OK;
	}

	return MGMT_OK;

}
