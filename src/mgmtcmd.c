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

extern struct helper_reg *helpers[];


#define MGMT_COMMANDS_NUM 3

struct mgmt_command mgmt_commands[MGMT_COMMANDS_NUM] = {

	{
		.words = {"exit", NULL},
		.help = "Exit the management console",
		.callback_func = mgmtcmd_exit,
	},

	{
		.words = { "show", "license", NULL},
		.help = "Display the license of this program",
		.callback_func = mgmtcmd_show_license,
	},

	{
		.words = { "show", "helpers", NULL},
		.help = "Display information about the loaded helpers",
		.callback_func = mgmtcmd_show_helpers,
	},

};

int mgmtcmd_register_all() {

	int i;


	for (i = 0; i < MGMT_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_commands[i]);
	}

	return MGMT_OK;
}


int mgmtcmd_exit(struct mgmt_connection *c) {
	
	char *bye_msg = "\r\nThanks for using packet-o-matic ! Bye !\r\n";
	mgmtsrv_send(c, bye_msg);
	mgmtsrv_close_connection(c);

	return MGMT_OK;

}



int mgmtcmd_show_license(struct mgmt_connection *c) {

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

int mgmtcmd_show_helpers(struct mgmt_connection *c) {

	mgmtsrv_send(c, "Loaded helpers : ");

	int i, first = 1;
	for (i = 0; i < MAX_HELPER; i++) {
		if (helpers[i]) {
			if (!first)
				mgmtsrv_send(c, ", ");
			else
				first = 0;
			mgmtsrv_send(c, match_get_name(i));
		}
	}
				

	return MGMT_OK;
}
