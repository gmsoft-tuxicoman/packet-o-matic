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


#include "mgmtcmd_helper.h"


#define MGMT_HELPER_COMMANDS_NUM 6

static struct mgmt_command mgmt_helper_commands[MGMT_HELPER_COMMANDS_NUM] = {

	{
		.words = { "helper", "show", NULL },
		.help = "Display information about loaded helpers",
		.callback_func = mgmtcmd_helper_show,
	},

	{
		.words = { "helper", "load", NULL },
		.help = "Load an helper module",
		.usage = "helper load <helper>",
		.callback_func = mgmtcmd_helper_load,
		.completion = mgmtcmd_helper_load_completion,
	},

	{
		.words = { "helper", "help", NULL },
		.help = "Get help for helpers",
		.usage = "helper help [helper]",
		.callback_func = mgmtcmd_helper_help,
		.completion = mgmtcmd_helper_loaded_completion,
	},

	{
		.words = { "helper", "parameter", "set", NULL},
		.help = "Change the value of a helper parameter",
		.usage = "helper parameter set <helper> <parameter> <value>",
		.callback_func = mgmtcmd_helper_parameter_set,
		.completion = mgmtcmd_helper_parameter_set_completion,
	},

	{
		.words = { "helper", "parameter", "reset", NULL},
		.help = "Reset a helper parameter to its default value",
		.usage = "helper parameter reset <helper> <parameter>",
		.callback_func = mgmtcmd_helper_parameter_reset,
		.completion = mgmtcmd_helper_parameter_set_completion,
	},

	{
		.words = { "helper", "unload", NULL },
		.help = "Unload an helper module",
		.usage = "helper unload <helper>",
		.callback_func = mgmtcmd_helper_unload,
		.completion = mgmtcmd_helper_loaded_completion,
	},

};

int mgmtcmd_helper_register_all() {

	int i;

	for (i = 0; i < MGMT_HELPER_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_helper_commands[i]);
	}

	return POM_OK;
}


int mgmtcmd_helper_show(struct mgmt_connection *c, int argc, char *argv[]) {

	mgmtsrv_send(c, "Loaded helpers : \r\n");

	helper_lock(0);

	int i;
	for (i = 0; i < MAX_HELPER; i++) {
		if (!helpers[i])
			continue;
		mgmtsrv_send(c, "  %s\r\n", match_get_name(i));

		struct helper_param *tmp = helpers[i]->params;

		if (!tmp) {
			mgmtsrv_send(c, "   no parameter\r\n");
			continue;
		}

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



int mgmtcmd_helper_load(struct mgmt_connection *c, int argc, char *argv[]) {


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
	} else {
		mgmtsrv_send(c, "Error while loading helper %s\r\n", argv[0]);
	}
	helper_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_helper_load_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("helper");
	return res;
}

int mgmtcmd_helper_help(struct mgmt_connection *c, int argc, char *argv[]) {

	helper_lock(0);

	int single = 0, id = 0, displayed = 0;
	if (argc >= 1) {
		single = 1;
		id = match_get_type(argv[0]); // Do not try to register the conntrack
		if (id == POM_ERR || !helpers[id]) {
			helper_unlock();
			mgmtsrv_send(c, "No conntrack %s registered\r\n", argv[0]);
			return POM_OK;
		}
	}

	for (; id < MAX_HELPER; id++) {
		char *name = match_get_name(id);
		if (!name || !helpers[id])
			continue;

		displayed++;

		mgmtsrv_send(c, "Helper %s :\r\n", name);

		struct helper_param* hp = helpers[id]->params;
		if (!hp) {
			mgmtsrv_send(c, "  no parameter for this helper\r\n");
		} else {
			while (hp) {
				char *ptype_name = ptype_get_name(hp->value->type);
				if (!ptype_name)
					ptype_name = "unknown";
				mgmtsrv_send(c, "  %s (%s) : %s (default : '%s')\r\n", hp->name, ptype_name, hp->descr, hp->defval);
				
				hp = hp->next;
			}
		}

		mgmtsrv_send(c, "\r\n");

		if (single)
			break;
		
	}
	helper_unlock();

	if (!displayed)
		mgmtsrv_send(c, "No helper loaded\r\n");

	return POM_OK;
}

int mgmtcmd_helper_parameter_set(struct mgmt_connection *c, int argc, char *argv[]) {
	
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

int mgmtcmd_helper_parameter_reset(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc != 2) 
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

	if (ptype_parse_val(p->value, p->defval) != POM_OK) {
		helper_unlock();
		mgmtsrv_send(c, "Unable to parse \"%s\"\r\n");
		return POM_OK;
	}
	helpers_serial++;
	helper_unlock();

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_helper_parameter_set_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	switch (argc) {
		case 3:
			res = mgmtcmd_helper_loaded_completion(2, argv);
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

int mgmtcmd_helper_unload(struct mgmt_connection *c, int argc, char *argv[]) {


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
	} else {
		mgmtsrv_send(c, "Error while unloading helper\r\n");
	}
	helper_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_helper_loaded_completion(int argc, char *argv[]) {

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

