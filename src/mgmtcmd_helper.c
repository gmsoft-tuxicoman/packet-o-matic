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

static struct mgmt_command mgmt_helper_commands[MGMT_HELPER_COMMANDS_NUM] = {

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
		.completion = mgmtcmd_load_helper_completion,
	},

	{
		.words = { "set", "helper", "parameter", NULL},
		.help = "Change the value of a helper parameter",
		.usage = "set helper parameter <helper> <parameter> <value>",
		.callback_func = mgmtcmd_set_helper_param,
		.completion = mgmtcmd_set_helper_param_completion,
	},

	{
		.words = { "unload", "helper", NULL },
		.help = "Unload an helper from the system",
		.usage = "unload helper <helper>",
		.callback_func = mgmtcmd_unload_helper,
		.completion = mgmtcmd_unload_helper_completion,
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

	helper_lock(0);

	int i;
	for (i = 0; i < MAX_HELPER; i++) {
		if (!helpers[i])
			continue;
		mgmtsrv_send(c, "  %s\r\n", match_get_name(i));

		struct helper_param *tmp = helpers[i]->params;
		while (tmp) {
			char buff[256];
			memset(buff, 0, sizeof(buff));
			ptype_print_val(tmp->value, buff, sizeof(buff));

			mgmtsrv_send(c, "   %s = %s %s\r\n", tmp->name, buff, tmp->value->unit);
			tmp = tmp->next;
		}
	}
		
	helper_unlock();

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

	helper_lock(1);
	if (helpers[id]) {
		helper_unlock();
		mgmtsrv_send(c, "Helper %s already loaded\r\n", argv[0]);
		return POM_OK;
	}

	if (helper_register(argv[0]) != POM_ERR) {
		mgmtsrv_send(c, "Helper %s registered successfully\r\n", argv[0]);
		helpers_serial++;
	} else {
		mgmtsrv_send(c, "Error while loading helper %s\r\n", argv[0]);
	}
	helper_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_load_helper_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("helper");
	return res;
}

int mgmtcmd_set_helper_param(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc != 3) 
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	helper_lock(1);
	if (!helpers[id]) {
		helper_unlock();
		mgmtsrv_send(c, "No helper with that name loaded\r\n");
		return POM_OK;
	}

	struct helper_param *p = helper_get_param(id, argv[1]);
	if (!p) {
		helper_unlock();
		mgmtsrv_send(c, "This parameter does not exists\r\n");
		return POM_OK;
	}

	if (ptype_parse_val(p->value, argv[2]) != POM_OK) {
		helper_unlock();
		mgmtsrv_send(c, "Invalid value given\r\n");
		return POM_OK;
	}
	helpers_serial++;
	helper_unlock();

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_set_helper_param_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	switch (argc) {
		case 3:
			res = mgmtcmd_unload_helper_completion(2, argv);
			break;

		case 4: {
			helper_lock(0);
			int i, helper_id = -1;
			for (i = 0; i < MAX_HELPER; i++) {
				if (helpers[i]) {
					char *name = match_get_name(i);
					if (!strcmp(argv[3], name)) {
						helper_id = i;
						break;
					}
				}

			}
			if (helper_id == -1) {
				helper_unlock();
				return NULL;
			}
			
			struct helper_param *p = helpers[helper_id]->params;
			while (p) {
				struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
				memset(item, 0, sizeof(struct mgmt_command_arg));
				item->word = malloc(strlen(p->name) + 1);
				strcpy(item->word, p->name);
				p = p->next;

				item->next = res;
				res = item;
			}
			helper_unlock();

			break;
		}
	}

	return res;

}

int mgmtcmd_unload_helper(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	helper_lock(1);
	if (id == POM_ERR || !helpers[id]) {
		helper_unlock();
		mgmtsrv_send(c, "Helper not loaded\r\n");
		return POM_OK;
	}

	if (helper_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Helper unloaded successfully\r\n");
		helpers_serial++;
	} else {
		mgmtsrv_send(c, "Error while unloading helper\r\n");
	}
	helper_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_unload_helper_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc != 2)
		return NULL;

	helper_lock(0);

	int i;
	for (i = 0; i < MAX_HELPER; i++) {
		if (helpers[i]) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			char *name = match_get_name(i);
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;
		}

	}

	helper_unlock();

	return res;
}

