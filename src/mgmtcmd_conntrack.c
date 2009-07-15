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

#define MGMT_CONNTRACK_COMMANDS_NUM 5

static struct mgmt_command mgmt_conntrack_commands[MGMT_CONNTRACK_COMMANDS_NUM] = {

	{
		.words = { "conntrack", "show", NULL },
		.help = "Show information about the loaded connection tracking modules",
		.callback_func = mgmtcmd_conntrack_show,
	},

	{
		.words = { "conntrack", "parameter", "set", NULL },
		.help = "Change the value of a conntrack parameter",
		.usage = "conntrack parameter set <conntrack> <parameter> <value>",
		.callback_func = mgmtcmd_conntrack_parameter_set,
		.completion = mgmtcmd_conntrack_parameter_set_completion,
	},

	{
		.words = { "conntrack", "load", NULL },
		.help = "Load a conntrack module",
		.usage = "conntrack load <conntrack>",
		.callback_func = mgmtcmd_conntrack_load,
		.completion = mgmtcmd_conntrack_load_completion,
	},

	{
		.words = { "conntrack", "help", NULL },
		.help = "Get help for conntracks",
		.usage = "conntrack help [type]",
		.callback_func = mgmtcmd_conntrack_help,
		.completion = mgmtcmd_conntrack_loaded_completion,
	},

	{
		.words = { "conntrack", "unload", NULL },
		.help = "Unload a conntrack module",
		.usage = "conntrack unload <conntrack>",
		.callback_func = mgmtcmd_conntrack_unload,
		.completion = mgmtcmd_conntrack_loaded_completion,
	},
		
};

int mgmtcmd_conntrack_register_all() {

	int i;

	for (i = 0; i < MGMT_CONNTRACK_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_conntrack_commands[i]);
	}

	return POM_OK;
}

int mgmtcmd_conntrack_show(struct mgmt_connection *c, int argc, char *argv[]) {
	
	int i;
	conntrack_lock(0);
	for (i = 0; i < MAX_CONNTRACK; i++) {
		if (conntracks[i]) {
			mgmtsrv_send(c, "%s (tracking %u connections)\r\n", match_get_name(i), conntracks[i]->refcount);
			struct conntrack_param *p = conntracks[i]->params;
			if (!p)
				mgmtsrv_send(c, "   No parameter for this conntrack module\r\n");
			while (p) {
				char buffer[256];
				memset(buffer, 0, sizeof(buffer));
				ptype_print_val(p->value, buffer, sizeof(buffer));
				mgmtsrv_send(c, "   %s = %s %s\r\n", p->name, buffer, p->value->unit);
				p = p->next;
			}

		}

	}
	conntrack_unlock();

	return POM_OK;
}

int mgmtcmd_conntrack_help(struct mgmt_connection *c, int argc, char *argv[]) {

	conntrack_lock(0);

	int single = 0, id = 0, displayed = 0;
	if (argc >= 1) {
		single = 1;
		id = match_get_type(argv[0]); // Do not try to register the conntrack
		if (id == POM_ERR || !conntracks[id]) {
			conntrack_unlock();
			mgmtsrv_send(c, "No conntrack %s registered\r\n", argv[0]);
			return POM_OK;
		}
	}

	for (; id < MAX_CONNTRACK; id++) {
		char *name = match_get_name(id);
		if (!name || !conntracks[id])
			continue;

		displayed++;

		mgmtsrv_send(c, "Conntrack %s :\r\n", name);

		struct conntrack_param* cp = conntracks[id]->params;
		if (!cp) {
			mgmtsrv_send(c, "  no parameter for this conntrack\r\n");
		} else {
			while (cp) {
				char *ptype_name = ptype_get_name(cp->value->type);
				if (!ptype_name)
					ptype_name = "unknown";
				mgmtsrv_send(c, "  %s (%s) : %s (default : '%s')\r\n", cp->name, ptype_name, cp->descr, cp->defval);
				
				cp = cp->next;
			}
		}

		mgmtsrv_send(c, "\r\n");

		if (single)
			break;
	}

	conntrack_unlock();

	if (!displayed)
		mgmtsrv_send(c, "No conntrack loaded\r\n");

	return POM_OK;
}

int mgmtcmd_conntrack_parameter_set(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc != 3) 
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);
	conntrack_lock(1);
	if (!conntracks[id]) {
		mgmtsrv_send(c, "No conntrack with that name loaded\r\n");
		conntrack_unlock();
		return POM_OK;
	}

	struct conntrack_param *p = conntrack_get_param(id, argv[1]);

	if (!p)
		mgmtsrv_send(c, "This parameter does not exists\r\n");
	else if (ptype_parse_val(p->value, argv[2]) != POM_OK) 
		mgmtsrv_send(c, "Invalid value given\r\n");

	conntrack_unlock();

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_conntrack_parameter_set_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	switch (argc) {
		case 3:
			res = mgmtcmd_conntrack_loaded_completion(2, argv);
			break;

		case 4: {
			conntrack_lock(0);
			int i, conntrack_id = -1;
			for (i = 0; i < MAX_CONNTRACK; i++) {
				if (conntracks[i]) {
					char *name = match_get_name(i);
					if (!strcmp(argv[3], name)) {
						conntrack_id = i;
						break;
					}
				}

			}
			if (conntrack_id == -1) {
				conntrack_unlock();
				return NULL;
			}
			
			struct conntrack_param *p = conntracks[conntrack_id]->params;
			while (p) {
				struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
				memset(item, 0, sizeof(struct mgmt_command_arg));
				item->word = malloc(strlen(p->name) + 1);
				strcpy(item->word, p->name);
				p = p->next;

				item->next = res;
				res = item;
			}
			conntrack_unlock();

			break;
		}
	}

	return res;

}
int mgmtcmd_conntrack_load(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Cannot load conntrack %s : corresponding match not loaded yet\r\n", argv[0]);
		return POM_OK;
	}

	conntrack_lock(1);
	if (conntracks[id]) {
		conntrack_unlock();
		mgmtsrv_send(c, "Conntrack %s already loaded\r\n", argv[0]);
		return POM_OK;
	}

	if (conntrack_register(argv[0]) != POM_ERR) {
		mgmtsrv_send(c, "Conntrack %s registered successfully\r\n", argv[0]);
	} else {
		mgmtsrv_send(c, "Error while loading conntrack %s\r\n", argv[0]);
	}
	conntrack_unlock();

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_conntrack_load_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("conntrack");
	return res;

}

int mgmtcmd_conntrack_unload(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	conntrack_lock(1);
	if (id == POM_ERR || !conntracks[id]) {
		conntrack_unlock();
		mgmtsrv_send(c, "Conntrack not loaded\r\n");
		return POM_OK;
	}

	if (conntracks[id]->refcount) {
		mgmtsrv_send(c, "Conntrack %s is still in use. Cannot unload it\r\n", argv[0]);
	} else if (conntrack_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Conntrack unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading conntrack\r\n");
	}
	conntrack_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_conntrack_loaded_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc != 2)
		return NULL;

	int i;
	conntrack_lock(0);
	for (i = 0; i < MAX_CONNTRACK; i++) {
		if (conntracks[i]) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			char *name = match_get_name(i);
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;
		}

	}
	conntrack_unlock();

	return res;
}
