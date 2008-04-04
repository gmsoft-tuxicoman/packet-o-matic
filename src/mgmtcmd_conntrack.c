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

#include "mgmtcmd_conntrack.h"
#include "conntrack.h"

#define MGMT_CONNTRACK_COMMANDS_NUM 4

struct mgmt_command mgmt_conntrack_commands[MGMT_CONNTRACK_COMMANDS_NUM] = {

	{
		.words = { "show", "conntracks", NULL },
		.help = "Show information about the loaded connection tracking modules",
		.callback_func = mgmtcmd_show_conntracks,
	},

	{
		.words = { "set", "conntrack", "parameter", NULL},
		.help = "Change the value of a conntrack parameter",
		.usage = "set conntrack parameter <conntrack> <parameter> <value>",
		.callback_func = mgmtcmd_set_conntrack_param,
	},

	{
		.words = { "load", "conntrack", NULL },
		.help = "Load a conntrack from the system",
		.usage = "load conntrack <conntrack>",
		.callback_func = mgmtcmd_load_conntrack,
	},

	{
		.words = { "unload", "conntrack", NULL },
		.help = "Unload a conntrack from the system",
		.usage = "unload conntrack <conntrack>",
		.callback_func = mgmtcmd_unload_conntrack,
	},
		
};

int mgmtcmd_conntrack_register_all() {

	int i;

	for (i = 0; i < MGMT_CONNTRACK_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_conntrack_commands[i]);
	}

	return POM_OK;
}

int mgmtcmd_show_conntracks(struct mgmt_connection *c, int argc, char *argv[]) {
	
	int i;
	for (i = 0; i < MAX_CONNTRACK; i++) {
		if (conntracks[i]) {
			mgmtsrv_send(c, "%s (tracking %u connections)\r\n", match_get_name(i), conntracks[i]->refcount);
			struct conntrack_param *p = conntracks[i]->params;
			if (!p)
				mgmtsrv_send(c, "   No parameter for this conntrack module\r\n");
			while (p) {
				char buffer[256];
				bzero(buffer, sizeof(buffer));
				ptype_print_val(p->value, buffer, sizeof(buffer));
				mgmtsrv_send(c, "   %s = %s %s\r\n", p->name, buffer, p->value->unit);
				p = p->next;
			}

		}

	}


	return POM_OK;
}

int mgmtcmd_set_conntrack_param(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc != 3) 
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);
	if (!conntracks[id]) {
		mgmtsrv_send(c, "No conntrack with that name loaded\r\n");
		return POM_OK;
	}

	struct conntrack_param *p = conntrack_get_param(id, argv[1]);
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

int mgmtcmd_load_conntrack(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Cannot load conntrack %s : corresponding match not loaded yet\r\n", argv[0]);
		return POM_OK;
	}

	if (conntracks[id]) {
		mgmtsrv_send(c, "Conntrack %s already loaded\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock();
	if (conntrack_register(argv[0]) != POM_ERR) {
		mgmtsrv_send(c, "Conntrack %s registered successfully\r\n", argv[0]);
	} else {
		mgmtsrv_send(c, "Error while loading conntrack %s\r\n", argv[0]);
	}
	reader_process_unlock();
	
	return POM_OK;

}
int mgmtcmd_unload_conntrack(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (id == POM_ERR || !conntracks[id]) {
		mgmtsrv_send(c, "Conntrack not loaded\r\n");
		return POM_OK;
	}

	if (conntracks[id]->refcount) {
		mgmtsrv_send(c, "Conntrack %s is still in use. Cannot unload it\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock();
	if (conntrack_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Conntrack unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading conntrack\r\n");
	}
	reader_process_unlock();
	
	return POM_OK;

}

