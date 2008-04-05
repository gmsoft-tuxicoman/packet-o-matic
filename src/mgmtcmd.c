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

#include "mgmtcmd_conntrack.h"
#include "mgmtcmd_input.h"
#include "mgmtcmd_helper.h"
#include "mgmtcmd_rule.h"
#include "mgmtcmd_target.h"

#include "ptype_uint64.h"

#define MGMT_COMMANDS_NUM 17

struct mgmt_command mgmt_commands[MGMT_COMMANDS_NUM] = {

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
		.words = { "enable", "debug",  NULL },
		.help = "Enable debug messages for this connection",
		.callback_func = mgmtcmd_enable_debug,
	},

	{
		.words = { "disable", "debug", NULL },
		.help = "Disable debug messages for this connection",
		.callback_func = mgmtcmd_disable_debug,
	},

	{
		.words = { "set", "debug", "level", NULL },
		.help = "Change the current debug level",
		.callback_func = mgmtcmd_set_debug_level,
		.usage = "set debug level <0-5>",
	},

	{
		.words = { "show", "debug", "level", NULL },
		.help = "Display the current debug level",
		.callback_func = mgmtcmd_show_debug_level,
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
	},

	{
		.words = { "load", "match", NULL },
		.help = "Load a match into the system",
		.usage = "load match <match>",
		.callback_func = mgmtcmd_load_match,
	},

	{
		.words = { "unload", "match", NULL },
		.help = "Unload a match from the system",
		.usage = "unload match <match>",
		.callback_func = mgmtcmd_unload_match,
	},

	{
		.words = { "load", "ptype", NULL },
		.help = "Load a ptype into the system",
		.usage = "load ptype <ptype>",
		.callback_func = mgmtcmd_load_ptype,
	},

	{
		.words = { "unload", "ptype", NULL },
		.help = "Unload a ptype from the system",
		.usage = "unload ptype <ptype>",
		.callback_func = mgmtcmd_unload_ptype,
	},

};

int mgmtcmd_register_all() {

	int i;


	for (i = 0; i < MGMT_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_commands[i]);
	}

	mgmtcmd_conntrack_register_all();
	mgmtcmd_input_register_all();
	mgmtcmd_helper_register_all();
	mgmtcmd_rule_register_all();
	mgmtcmd_target_register_all();

	return POM_OK;
}


int mgmtcmd_help(struct mgmt_connection *c, int argc, char *argv[]) {
	
	return mgmtcmd_print_help(c, cmds, NULL);
}

int mgmtcmd_print_help(struct mgmt_connection *c, struct mgmt_command *start, struct mgmt_command *end) {

	int i, wordslen, wordslenmax = 0, helplenmax = 0;
	struct mgmt_command *tmp = start;
	// calculate max length of first part
	while (tmp && !(tmp->prev == end && end)) {
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

	tmp = start;

	while (tmp && !(tmp->prev == end && end)) {

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

int mgmtcmd_enable_debug(struct mgmt_connection *c, int argc, char *argv[]) {

	if (c->flags & MGMT_FLAG_MONITOR) {
		mgmtsrv_send(c, "Debug already enabled\r\n");
		return POM_OK;
	}

	c->flags |= MGMT_FLAG_MONITOR;
	return POM_OK;
}

int mgmtcmd_disable_debug(struct mgmt_connection *c, int argc, char *argv[]) {

	if (!(c->flags & MGMT_FLAG_MONITOR)) {
		mgmtsrv_send(c, "Debug already disabled\r\n");
		return POM_OK;
	}
	c->flags &= ~MGMT_FLAG_MONITOR;
	return POM_OK;
}

int mgmtcmd_set_debug_level(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc != 1)
		return MGMT_USAGE;

	unsigned int new_level;
	if (sscanf(argv[0], "%u", &new_level ) < 1)
		return MGMT_USAGE;
	if (new_level > 5)
		return MGMT_USAGE;

	debug_level = new_level;

	return POM_OK;
}

int mgmtcmd_show_debug_level(struct mgmt_connection *c, int argc, char *argv[]) {

	mgmtsrv_send(c, "Debug level is ");

	switch (debug_level) {
		case 0:
			mgmtsrv_send(c, "0 : No output at all\r\n");
			break;
		case 1:
			mgmtsrv_send(c, "1 : Errors only\r\n");
			break;
		case 2:
			mgmtsrv_send(c, "2 : Warnings and errors\r\n");
			break;
		case 3:
			mgmtsrv_send(c, "3 : Warnings, errors and general information messages\r\n");
			break;
		case 4:
			mgmtsrv_send(c, "4 : Warnings, errors, info and debug messages\r\n");
			break;
		case 5:
			mgmtsrv_send(c, "5 : Troubleshooting debug level\r\n");
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

	struct core_param *p = core_params;

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


int mgmtcmd_load_match(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (id != POM_ERR) {
		mgmtsrv_send(c, "Match %s already loaded\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock();
	id = match_register(argv[0]);
	if (id != POM_ERR) {
		mgmtsrv_send(c, "Match %s registered with id %u\r\n", argv[0], id);
	} else {
		mgmtsrv_send(c, "Error while loading match %s\r\n", argv[0]);
	}
	reader_process_unlock();
	
	return POM_OK;

}
int mgmtcmd_unload_match(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Match not loaded\r\n");
		return POM_OK;
	}

	if (conntracks[id] && conntracks[id]->refcount) {
		mgmtsrv_send(c, "Conntrack %s is still in use. Cannot unload match\r\n", argv[0]);
		return POM_OK;
	}

	if (matchs[id]->refcount) {
		mgmtsrv_send(c, "Match %s is still in use. Cannot unload it\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock();
	if (match_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Match unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading match\r\n");
	}
	reader_process_unlock();
	
	return POM_OK;

}

int mgmtcmd_load_ptype(struct mgmt_connection *c, int argc, char*argv[]) {

	if (argc != 1)
		return MGMT_USAGE;
	
	if (ptype_get_type(argv[0]) != POM_ERR) {
		mgmtsrv_send(c, "Ptype %s is already registered\r\n", argv[0]);
		return POM_OK;
	}

	int id = ptype_register(argv[0]);
	if (id == POM_ERR)
		mgmtsrv_send(c, "Error while loading ptype %s\r\n", argv[0]);
	else
		mgmtsrv_send(c, "Ptype %s regitered with id %u\r\n", argv[0], id);

	return POM_OK;

}

int mgmtcmd_unload_ptype(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = ptype_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Ptype %s not loaded\r\n", argv[0]);
		return POM_OK;
	}

	if (ptypes[id]->refcount) {
		mgmtsrv_send(c, "Ptype %s is still in use. Cannot unload it\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock();
	if (ptype_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Ptype unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading ptype\r\n");
	}
	reader_process_unlock();
	
	return POM_OK;

}

