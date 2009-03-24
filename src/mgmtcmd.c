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


#include "common.h"
#include "mgmtsrv.h"
#include "mgmtcmd.h"
#include "match.h"
#include "version.h"
#include "core_param.h"

#include <dirent.h>

#include "mgmtcmd_conntrack.h"
#include "mgmtcmd_input.h"
#include "mgmtcmd_helper.h"
#include "mgmtcmd_rule.h"
#include "mgmtcmd_target.h"
#include "mgmtcmd_datastore.h"

#include "ptype_uint64.h"

#define MGMT_COMMANDS_NUM 17

static struct mgmt_command mgmt_commands[MGMT_COMMANDS_NUM] = {

	{
		.words = { "exit", NULL },
		.help = "Exit the management console",
		.callback_func = mgmtcmd_exit,
	},
	
	{
		.words = { "help", NULL },
		.help = "Display the help",
		.callback_func = mgmtcmd_help,
	},

	{
		.words = { "show", "license", NULL },
		.help = "Display the license of this program",
		.callback_func = mgmtcmd_show_license,
	},

	{
		.words = { "set", "password", NULL },
		.help = "Set the password to access the CLI",
		.callback_func = mgmtcmd_set_password,
		.usage = "set password <password>",
	},

	{
		.words = { "unset", "password", NULL },
		.help = "Unset the password to access the CLI",
		.callback_func = mgmtcmd_unset_password,
	},

	{
		.words = { "set", "debug", "level", NULL },
		.help = "Change the debug level of the CLI",
		.callback_func = mgmtcmd_set_debug_level,
		.usage = "set debug level <off,0-5>",
		.completion = mgmtcmd_set_debug_level_completion,
	},

	{
		.words = { "show", "debug", "level", NULL },
		.help = "Display the current debug level",
		.callback_func = mgmtcmd_show_debug_level,
	},

	{
		.words = { "set", "console", "debug", NULL },
		.help = "Change the debug level of the main console",
		.callback_func = mgmtcmd_set_console_debug,
		.usage = "set console debug <off,0-5>",
		.completion = mgmtcmd_set_debug_level_completion,
	},

	{
		.words = { "write", "config", NULL },
		.help = "Write the configuration file",
		.callback_func = mgmtcmd_write_config,
		.usage = "write config [filename]",
	},

	{
		.words = { "halt", NULL },
		.help = "Halt the program",
		.callback_func = mgmtcmd_halt,
	},

	{
		.words = { "show", "core", "parameters", NULL },
		.help = "Show the core parameters",
		.callback_func = mgmtcmd_show_core_parameters,
	},

	{
		.words = { "set", "core", "parameter", NULL },
		.help = "Change the value of a core parameter",
		.callback_func = mgmtcmd_set_core_parameter,
		.usage = "set core parameter <parameter> <value>",
		.completion = mgmtcmd_set_core_parameter_completion,
	},

	{
		.words = { "load", "match", NULL },
		.help = "Load a match into the system",
		.usage = "load match <match>",
		.callback_func = mgmtcmd_load_match,
		.completion = mgmtcmd_load_match_completion,
	},

	{
		.words = { "unload", "match", NULL },
		.help = "Unload a match from the system",
		.usage = "unload match <match>",
		.callback_func = mgmtcmd_unload_match,
		.completion = mgmtcmd_unload_match_completion,
	},

	{
		.words = { "load", "ptype", NULL },
		.help = "Load a ptype into the system",
		.usage = "load ptype <ptype>",
		.callback_func = mgmtcmd_load_ptype,
		.completion = mgmtcmd_load_ptype_completion,
	},

	{
		.words = { "unload", "ptype", NULL },
		.help = "Unload a ptype from the system",
		.usage = "unload ptype <ptype>",
		.callback_func = mgmtcmd_unload_ptype,
		.completion = mgmtcmd_unload_ptype_completion,
	},

	{
		.words = { "show", "version", NULL },
		.help = "Show packet-o-matic version",
		.callback_func = mgmtcmd_show_version,
	},

};

int mgmtcmd_register_all() {

	int i;

	for (i = 0; i < MGMT_COMMANDS_NUM; i++) {
		if (mgmtsrv_register_command(&mgmt_commands[i]) == POM_ERR)
			return POM_ERR;
	}

	mgmtcmd_conntrack_register_all();
	mgmtcmd_input_register_all();
	mgmtcmd_helper_register_all();
	mgmtcmd_rule_register_all();
	mgmtcmd_target_register_all();
	mgmtcmd_datastore_register_all();

	return POM_OK;
}


int mgmtcmd_help(struct mgmt_connection *c, int argc, char *argv[]) {
	
	return mgmtcmd_print_help(c, cmds, 1);
}

int mgmtcmd_print_help(struct mgmt_connection *c, struct mgmt_command *commands, int show_all) {

	int i, wordslen, wordslenmax = 0, helplenmax = 0;
	struct mgmt_command *tmp = commands;
	// calculate max length of first part
	while (tmp) {
		if (!show_all && !tmp->matched) {
			tmp = tmp->next;
			continue;
		}

		if (tmp->usage) {
			wordslen = strlen(tmp->usage) + 1;
		} else {
			wordslen = 0;
			for (i = 0; tmp->words[i] ;i++) {
				wordslen += strlen(tmp->words[i]) + 1;
			}
		}

		if (wordslenmax < wordslen) {
			wordslenmax = wordslen;
		}

		if (helplenmax < strlen(tmp->help) + 3) {
			helplenmax = strlen(tmp->help) + 3;
		}
		
		tmp = tmp->next;
	}

	tmp = commands;

	while (tmp) {
		if (!show_all && !tmp->matched) {
			tmp = tmp->next;
			continue;
		}

		if (tmp->usage) {
			mgmtsrv_send(c, tmp->usage);
			wordslen = strlen(tmp->usage) ;
		} else {
			wordslen = 0;
			for (i = 0; tmp->words[i]; i++) {
				mgmtsrv_send(c, "%s ", tmp->words[i]); 
				wordslen += strlen(tmp->words[i]) + 1;
			}
		}
		if (wordslenmax + helplenmax > c->win_x) {
			mgmtsrv_send(c, ":\r\n\t%s\r\n", tmp->help);
		} else {
			for (i = wordslen; i < wordslenmax; i++) {
				mgmtsrv_send(c, " ");
			}
			mgmtsrv_send(c, ": %s\r\n", tmp->help);
		}

		tmp = tmp->next;
	}


	return POM_OK;

}


int mgmtcmd_exit(struct mgmt_connection *c, int argc, char *argv[]) {
	
	char *bye_msg = "\r\nThanks for using packet-o-matic ! Bye !\r\n";
	mgmtsrv_send(c, bye_msg);
	mgmtsrv_close_connection(c);

	return POM_OK;

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
	return POM_OK;
}

int mgmtcmd_set_password(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc != 1)
		return MGMT_USAGE;

	mgmtsrv_set_password(argv[0]);

	return POM_OK;
}

int mgmtcmd_unset_password(struct mgmt_connection *c, int argc, char *argv[]) {

	mgmtsrv_set_password(NULL);
	return POM_OK;
}

int mgmtcmd_set_debug_level(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc != 1)
		return MGMT_USAGE;

	if (!strcasecmp(argv[0], "off")) {
		c->debug_level = 0;
		return POM_OK;
	}

	unsigned int new_level;
	if (sscanf(argv[0], "%u", &new_level ) < 1)
		return MGMT_USAGE;
	if (new_level > 5)
		return MGMT_USAGE;

	c->debug_level = new_level;

	return POM_OK;
}

int mgmtcmd_set_console_debug(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc != 1)
		return MGMT_USAGE;

	if (!strcasecmp(argv[0], "off")) {
		console_debug_level = 0;
		return POM_OK;
	}

	unsigned int new_level;
	if (sscanf(argv[0], "%u", &new_level ) < 1)
		return MGMT_USAGE;
	if (new_level > 5)
		return MGMT_USAGE;

	console_debug_level = new_level;

	return POM_OK;
}

struct mgmt_command_arg *mgmtcmd_set_debug_level_completion(int argc, char *argv[]) {

	if (argc != 3)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_completion_int_range(0, 6);

	return res;

}

int mgmtcmd_show_debug_level(struct mgmt_connection *c, int argc, char *argv[]) {

	mgmtsrv_send(c, "Debug level is ");

	switch (c->debug_level) {
		case 0:
			mgmtsrv_send(c, "off\r\n");
			break;
		case 1:
			mgmtsrv_send(c, "1 (Errors only)\r\n");
			break;
		case 2:
			mgmtsrv_send(c, "2 (Warnings and errors)\r\n");
			break;
		case 3:
			mgmtsrv_send(c, "3 (Warnings, errors and general information messages)\r\n");
			break;
		case 4:
			mgmtsrv_send(c, "4 (Warnings, errors, info and debug messages)\r\n");
			break;
		case 5:
			mgmtsrv_send(c, "5 (Troubleshooting debug level)\r\n");
			break;
		default:
			mgmtsrv_send(c, "invalid\r\n");

	}

	return POM_OK;
}

int mgmtcmd_write_config(struct mgmt_connection *c, int argc, char *argv[]) {

	int result;

	if (argc < 1)
		result = config_write(main_config, NULL);
	else
		result = config_write(main_config, argv[0]);
	
	if (result == POM_ERR)
		mgmtsrv_send(c, "Error while writing configuration file %s\r\n", main_config->filename);
	else
		mgmtsrv_send(c, "Configuration written in %s\r\n", main_config->filename);


	return POM_OK;

}

int mgmtcmd_halt(struct mgmt_connection *c, int argc, char *argv[]) {

	mgmtsrv_send(c, "Please wait while packet-o-matic is stopping ...\r\n");
	halt();
	return POM_OK;
}

int mgmtcmd_show_core_parameters(struct mgmt_connection *c, int argc, char *argv[]) {

	struct core_param *p = core_param_get_head();

	while (p) {
		char buff[2048];
		ptype_print_val(p->value, buff, sizeof(buff) - 1);
		mgmtsrv_send(c, "  %s : %s %s\r\n", p->name, buff, p->value->unit);
		p = p->next;
	}

	return POM_OK;
}

int mgmtcmd_set_core_parameter(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 2)
		return MGMT_USAGE;

	char buffer[2048];
	if (core_set_param_value(argv[0], argv[1], buffer, sizeof(buffer) - 1) == POM_ERR) {
		mgmtsrv_send(c, "Unable to change parameter : %s\r\n", buffer);
	}

	return POM_OK;
}

struct mgmt_command_arg *mgmtcmd_set_core_parameter_completion(int argc, char *argv[]) {


	if (argc != 3)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	
	struct core_param *p = core_param_get_head();
	while (p) {
		struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
		memset(item, 0, sizeof(struct mgmt_command_arg));
		item->word = malloc(strlen(p->name) + 1);
		strcpy(item->word, p->name);
		item->next = res;
		res = item;
		p = p->next;
	}

	return res;
}

int mgmtcmd_load_match(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (id != POM_ERR) {
		mgmtsrv_send(c, "Match %s already loaded\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock(); // we need to lock the process lock because match dependencies will be updated
	match_lock(1);
	id = match_register(argv[0]);
	if (id != POM_ERR) {
		mgmtsrv_send(c, "Match %s registered with id %u\r\n", argv[0], id);
	} else {
		mgmtsrv_send(c, "Error while loading match %s\r\n", argv[0]);
	}
	match_unlock(0);
	reader_process_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_load_match_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("match");
	return res;

}

int mgmtcmd_unload_match(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	if (!strcmp(argv[0], "undefined")) {
		mgmtsrv_send(c, "Match undefined cannot be unloaded because it's a system match\r\n");
		return POM_OK;
	}

	int id = match_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Match not loaded\r\n");
		return POM_OK;
	}

	if (conntracks[id] && conntracks[id]->refcount) {
		mgmtsrv_send(c, "Conntrack %s is still in use. Cannot unload match\r\n", argv[0]);
		return POM_OK;
	}

	if (matches[id]->refcount) {
		mgmtsrv_send(c, "Match %s is still in use. Cannot unload it\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock(); // need to lock because match dependencies will be updated
	if (match_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Match unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading match\r\n");
	}
	reader_process_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_unload_match_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc != 2)
		return NULL;

	int i;
	for (i = 0; i < MAX_MATCH; i++) {
		if (matches[i]) {
			char *name = match_get_name(i);
			if (!strcmp(name, "undefined"))
				continue;
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;
		}

	}

	return res;
}

int mgmtcmd_load_ptype(struct mgmt_connection *c, int argc, char*argv[]) {

	if (argc != 1)
		return MGMT_USAGE;

	ptype_lock(1);

	if (ptype_get_type(argv[0]) != POM_ERR) {
		ptype_unlock();
		mgmtsrv_send(c, "Ptype %s is already registered\r\n", argv[0]);
		return POM_OK;
	}

	int id = ptype_register(argv[0]);
	if (id == POM_ERR)
		mgmtsrv_send(c, "Error while loading ptype %s\r\n", argv[0]);
	else
		mgmtsrv_send(c, "Ptype %s regitered with id %u\r\n", argv[0], id);

	ptype_unlock();

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_load_ptype_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("ptype");
	return res;

}

int mgmtcmd_show_version(struct mgmt_connection *c, int argc, char*argv[]) {

	if (argc != 0)
		return MGMT_USAGE;

	mgmtsrv_send(c, "This is packet-o-matic " POM_VERSION "\r\n");

	return POM_OK;
}

int mgmtcmd_unload_ptype(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	ptype_lock(1);

	int id = ptype_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Ptype %s not loaded\r\n", argv[0]);
	} else 	if (ptype_get_refcount(id)) {
		mgmtsrv_send(c, "Ptype %s is still in use. Cannot unload it\r\n", argv[0]);
	} else 	if (ptype_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Ptype unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading ptype\r\n");
	}

	ptype_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_unload_ptype_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc != 2)
		return NULL;

	ptype_lock(0);

	int i;
	for (i = 0; i < MAX_PTYPE; i++) {
		char *name = ptype_get_name(i);
		if (name) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;
		}

	}

	ptype_unlock();

	return res;
}

struct mgmt_command_arg* mgmtcmd_list_modules(char *type) {


	struct mgmt_command_arg *res = NULL;

	char **list = list_modules(type);

	if (!list)
		return NULL;

	int i;
	for (i = 0; list[i]; i++) {
		struct mgmt_command_arg* item = malloc(sizeof(struct mgmt_command_arg));
		memset(item, 0, sizeof(struct mgmt_command_arg));
		item->word = malloc(strlen(list[i]) + 1);
		strcpy(item->word, list[i]);
		item->next = res;
		res = item;
		free(list[i]);
	}
	
	free(list);

	return res;
}

struct mgmt_command_arg *mgmtcmd_completion_int_range(int start, int count) {
	struct mgmt_command_arg* res = NULL;
	int i, end = start + count;
	for (i = start; i < end; i++) {
		char temp[64];
		snprintf(temp, sizeof(temp) - 1, "%u", i);
		struct mgmt_command_arg* item = malloc(sizeof(struct mgmt_command_arg));
		memset(item, 0, sizeof(struct mgmt_command_arg));
		item->word = malloc(strlen(temp) + 1);
		strcpy(item->word, temp);

		item->next = res;
		res = item;
	}

	return res;
}
