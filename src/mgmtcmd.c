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
#include "main.h"
#include "helper.h"
#include "match.h"
#include "ptype.h"
#include "main.h"

extern struct helper_reg *helpers[];


#define MGMT_COMMANDS_NUM 8

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

	{
		.words = { "unload", "helper", NULL },
		.help = "Unload an helper from the system",
		.usage = "unload helper <helper_name>",
		.callback_func = mgmtcmd_unload_helper,
	},

	{
		.words = { "show", "rules", NULL },
		.help = "Display all the configured rules",
		.callback_func = mgmtcmd_show_rules,
	},

};

int mgmtcmd_register_all() {

	int i;


	for (i = 0; i < MGMT_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_commands[i]);
	}

	return MGMT_OK;
}


int mgmtcmd_help(struct mgmt_connection *c, int argc, char *argv[]) {
	
	int i, wordslen, wordslenmax=0;

	struct mgmt_command *tmp = cmds;
	while (tmp) {
		wordslen=0;
		for (i = 0; tmp->words[i] ;i++) {
			wordslen += strlen(tmp->words[i]) + 1;
		}
		
		if (wordslenmax < wordslen) {
			wordslenmax = wordslen;
		}
		
		tmp = tmp->next;
	}

	tmp = cmds;

	while (tmp) {
		wordslen=0;
		for (i = 0; tmp->words[i] ;i++) {
			mgmtsrv_send(c, tmp->words[i]); 
			mgmtsrv_send(c, " "); 
			wordslen += strlen(tmp->words[i]) + 1;
		}

		for (i = wordslen; i <= wordslenmax; i++) {
			mgmtsrv_send(c, " ");
		}

		mgmtsrv_send(c, ": ");
		mgmtsrv_send(c, tmp->help);
		mgmtsrv_send(c, "\r\n");

		tmp = tmp->next;
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

	reader_process_lock();
	if (helper_register(argv[0]) != H_ERR) {
		mgmtsrv_send(c, "Helper registered successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while loading helper\r\n");
	}
	reader_process_unlock();
	
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

int mgmtcmd_unload_helper(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = match_get_type(argv[0]);

	if (!helpers[id]) {
		mgmtsrv_send(c, "Helper not loaded\r\n");
		return MGMT_OK;
	}
	reader_process_lock();
	if (helper_unregister(id) != H_ERR) {
		mgmtsrv_send(c, "Helper unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading helper\r\n");
	}
	reader_process_unlock();
	
	return MGMT_OK;

}

int mgmtcmd_show_rule_print_node(struct mgmt_connection *c, struct rule_node *n, struct rule_node *last, char *prepend) {

	if (n == last)
		return 0;


	while (n != last) {

		if (!n->b) {
			if (n->op != RULE_OP_TAIL) {
				if (n->op & RULE_OP_NOT)
					mgmtsrv_send(c, "!");
				mgmtsrv_send(c, match_get_name(n->layer));
				if (n->match) {
					mgmtsrv_send(c, ".");
					mgmtsrv_send(c, n->match->field->name);
					mgmtsrv_send(c, " ");
					mgmtsrv_send(c, ptype_get_op_name(n->match->op));
					mgmtsrv_send(c, " ");
					const int bufflen = 256;
					char buff[bufflen];
					ptype_print_val(n->match->value, buff, bufflen);
					mgmtsrv_send(c, buff);

				}
				mgmtsrv_send(c, "\r\n");
			}
			n = n->a;

		} else {
			// fin the last one that needs to be processed
			struct rule_node *new_last = NULL, *rn = n;
			while (rn && rn != last) {
				if (rn->op == RULE_OP_TAIL)
					new_last = rn;
				rn = rn->a;
			}
			if (n->op & RULE_OP_NOT) {
				if (n->op & RULE_OP_OR)
					mgmtsrv_send(c, "!or -- ");
				else if (n->op & RULE_OP_AND)
					mgmtsrv_send(c, "!and - ");
			} else {
				if (n->op & RULE_OP_OR)
					mgmtsrv_send(c, "or --- ");
				else if (n->op & RULE_OP_AND)
					mgmtsrv_send(c, "and -- ");
			}
			
			char *prepend_a = " |     ";
			char *prepend_b = "       ";

			char *my_prepend = malloc(strlen(prepend) + strlen(prepend_a) + 1);
			strcpy(my_prepend, prepend);
			strcat(my_prepend, prepend_a);
			mgmtcmd_show_rule_print_node(c, n->a, new_last, my_prepend);

			mgmtsrv_send(c, prepend);
			mgmtsrv_send(c, " `---- ");
			strcpy(my_prepend, prepend);
			strcat(my_prepend, prepend_b);
			mgmtcmd_show_rule_print_node(c, n->b, new_last, my_prepend);
			free(my_prepend);
			n = new_last;
		}
		if (n && n->op != RULE_OP_TAIL) {
			mgmtsrv_send(c, prepend);
		}
	}

	return 0;
}

int mgmtcmd_show_rules(struct mgmt_connection *c, int argc, char *argv[]) {
	
	struct rule_list *rl = main_config->rules;

	unsigned int rule_num = 0;
	char buff[256];

	while (rl) {
		sprintf(buff, "%u", rule_num);
		mgmtsrv_send(c, "Rule ");
		mgmtsrv_send(c, buff);
		mgmtsrv_send(c, " : \r\n");

		struct rule_node *last, *rn = rl->node;
		while (rn){
			if (rn->op == RULE_OP_TAIL)
				last = rn;
			rn = rn->a;
		}

		char *prepend = "  ";
		mgmtsrv_send(c, prepend);
		mgmtcmd_show_rule_print_node(c, rl->node, NULL, prepend);

		mgmtsrv_send(c, "\r\n");

		rl = rl->next;
		rule_num++;
	}

	return MGMT_OK;
}
