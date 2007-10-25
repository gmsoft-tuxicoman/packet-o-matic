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

#define MGMT_COMMANDS_NUM 22

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
		.usage = "set helper parameter <helper> <parameter> <value>",
		.callback_func = mgmtcmd_set_helper_param,
	},

	{
		.words = { "unload", "helper", NULL },
		.help = "Unload an helper from the system",
		.usage = "unload helper <helper>",
		.callback_func = mgmtcmd_unload_helper,
	},

	{
		.words = { "show", "rules", NULL },
		.help = "Display all the configured rules",
		.callback_func = mgmtcmd_show_rules,
		.usage = "show rules [tree | flat]",
	},
	
	{
		.words = { "set", "rule", NULL },
		.help = "Change a rule",
		.callback_func = mgmtcmd_set_rule,
		.usage = "set rule <rule id> <rule>",
	},

	{
		.words = { "show", "input", NULL },
		.help = "Display informations about the input in use",
		.callback_func = mgmtcmd_show_input,
	},

	{
		.words = { "show", "targets", NULL },
		.help = "Display informations about the targets in every rule",
		.callback_func = mgmtcmd_show_targets,
	},

	{
		.words = { "disable", "rule", NULL },
		.help = "Disable a rule",
		.callback_func = mgmtcmd_disable_rule,
		.usage = "disable rule <rule id>",
	},

	{
		.words = { "enable", "rule", NULL },
		.help = "Enable a rule",
		.callback_func = mgmtcmd_enable_rule,
		.usage = "enable rule <rule id>",
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
		.words = { "start", "input", NULL },
		.help = "Start the input",
		.callback_func = mgmtcmd_start_input,
	},

	{
		.words = { "stop", "input", NULL },
		.help = "Stop the input",
		.callback_func = mgmtcmd_stop_input,
	},

	{
		.words = { "write", "config", NULL },
		.help = "Write the configuration file",
		.callback_func = mgmtcmd_write_config,
		.usage = "write config [filename]",
	},
};

int mgmtcmd_register_all() {

	int i;


	for (i = 0; i < MGMT_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_commands[i]);
	}

	return POM_OK;
}


int mgmtcmd_help(struct mgmt_connection *c, int argc, char *argv[]) {
	
	int i, wordslen, wordslenmax = 0;

	struct mgmt_command *tmp = cmds;
	while (tmp) {
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
		
		tmp = tmp->next;
	}

	tmp = cmds;

	while (tmp) {
		if (tmp->usage) {
			mgmtsrv_send(c, tmp->usage);
			wordslen = strlen(tmp->usage) ;
		} else {
			wordslen = 0;
			for (i = 0; tmp->words[i] ;i++) {
				mgmtsrv_send(c, tmp->words[i]); 
				mgmtsrv_send(c, " "); 
				wordslen += strlen(tmp->words[i]) + 1;
			}
		}

		for (i = wordslen; i < wordslenmax; i++) {
			mgmtsrv_send(c, " ");
		}

		mgmtsrv_send(c, ": ");
		mgmtsrv_send(c, tmp->help);
		mgmtsrv_send(c, "\r\n");

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

	if (id == -1) {
		mgmtsrv_send(c, "Cannot load helper : corresponding match not loaded yet\r\n");
		return POM_OK;
	}

	if (helpers[id]) {
		mgmtsrv_send(c, "Helper already loaded\r\n");
		return POM_OK;
	}

	reader_process_lock();
	if (helper_register(argv[0]) != POM_ERR) {
		mgmtsrv_send(c, "Helper registered successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while loading helper\r\n");
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

	if (!helpers[id]) {
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

int mgmtcmd_show_rule_print_node_flat(struct mgmt_connection *c, struct rule_node *n, struct rule_node *last) {

	if (n == last)
		return 0;


	int display_parenthesis = 0;

	if (last != NULL && n->a && n->a->op != RULE_OP_TAIL)
		display_parenthesis = 1;


	if (n->op & RULE_OP_NOT && n->b) {
		mgmtsrv_send(c, "!");
		display_parenthesis = 1;
	}



	if (display_parenthesis)
		mgmtsrv_send(c, "(");

	while (n != last) {

		if (!n->b) {
			if (n->op != RULE_OP_TAIL) {
				if (n->op & RULE_OP_NOT)
					mgmtsrv_send(c, "!");
				mgmtsrv_send(c, match_get_name(n->layer));
				if (n->match) {
					const int bufflen = 256;
					char buff[bufflen];
					ptype_print_val(n->match->value, buff, bufflen);
					mgmtsrv_send(c, ".%s %s %s" , n->match->field->name, ptype_get_op_sign(n->match->op), buff);

				}
			}
			n = n->a;

		} else {
			// fin the last one that needs to be processed
			struct rule_node *new_last = NULL, *rn = n;
			int depth = 0;
			while (rn && rn != last) {
				if (rn->b) {
					depth++;
				} else if (rn->op == RULE_OP_TAIL) {
					depth--;
					if (depth == 0) {
						new_last = rn;
						break;
					}
				}
				rn = rn->a;
			}

			if (n->op & RULE_OP_NOT)
				mgmtsrv_send(c, "!(");

			mgmtcmd_show_rule_print_node_flat(c, n->a, new_last);
			if (n->op & RULE_OP_OR)
				mgmtsrv_send(c, " or ");
			else if (n->op & RULE_OP_AND)
				mgmtsrv_send(c, " and ");

			mgmtcmd_show_rule_print_node_flat(c, n->b, new_last);
			if (n->op & RULE_OP_NOT)
				mgmtsrv_send(c, ")");

			n = new_last;
		}
		if (n && n->op != RULE_OP_TAIL) {
			mgmtsrv_send(c, " | ");
		}
	}
	if (display_parenthesis)
		mgmtsrv_send(c, ")");
	return POM_OK;
}

int mgmtcmd_show_rule_print_node_tree(struct mgmt_connection *c, struct rule_node *n, struct rule_node *last, char *prepend) {

	if (n == last)
		return 0;


	while (n != last) {

		if (!n->b) {
			if (n->op != RULE_OP_TAIL) {
				if (n->op & RULE_OP_NOT)
					mgmtsrv_send(c, "!");
				mgmtsrv_send(c, match_get_name(n->layer));
				if (n->match) {
					const int bufflen = 256;
					char buff[bufflen];
					ptype_print_val(n->match->value, buff, bufflen);
					mgmtsrv_send(c, ".%s %s %s" , n->match->field->name, ptype_get_op_sign(n->match->op), buff);

				}
				mgmtsrv_send(c, "\r\n");
			}
			n = n->a;

		} else {
			// fin the last one that needs to be processed
			struct rule_node *new_last = NULL, *rn = n;
			int depth = 0;
			while (rn && rn != last) {
				if (rn->b) {
					depth++;
				} else if (rn->op == RULE_OP_TAIL) {
					depth--;
					if (depth == 0) {
						new_last = rn;
						break;
					}
				}
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
			mgmtcmd_show_rule_print_node_tree(c, n->a, new_last, my_prepend);

			mgmtsrv_send(c, prepend);
			mgmtsrv_send(c, " `---- ");
			strcpy(my_prepend, prepend);
			strcat(my_prepend, prepend_b);
			mgmtcmd_show_rule_print_node_tree(c, n->b, new_last, my_prepend);
			free(my_prepend);
			n = new_last;
		}
		if (n && n->op != RULE_OP_TAIL) {
			mgmtsrv_send(c, prepend);
		}
	}

	return POM_OK;
}

int mgmtcmd_show_rules(struct mgmt_connection *c, int argc, char *argv[]) {
	
	struct rule_list *rl = main_config->rules;

	unsigned int rule_num = 0;

	while (rl) {
		mgmtsrv_send(c, "Rule %u", rule_num);
		if (!rl->enabled)
			mgmtsrv_send(c, " (disabled)");
		mgmtsrv_send(c, " : \r\n");

		struct rule_node *last, *rn = rl->node;
		while (rn){
			if (rn->op == RULE_OP_TAIL)
				last = rn;
			rn = rn->a;
		}

		char *prepend = "  ";
		mgmtsrv_send(c, prepend);
		if (argc > 0) {
			if (!strcmp(argv[0], "tree")) {
				mgmtcmd_show_rule_print_node_tree(c, rl->node, NULL, prepend);
			} else if (!strcmp(argv[0], "flat")) {
				mgmtcmd_show_rule_print_node_flat(c, rl->node, NULL);
				mgmtsrv_send(c, "\r\n");
			} else
				return MGMT_USAGE;
		} else
			mgmtcmd_show_rule_print_node_tree(c, rl->node, NULL, prepend);

		mgmtsrv_send(c, "\r\n");

		rl = rl->next;
		rule_num++;
	}

	return POM_OK;
}

struct rule_node *mgmtcmd_set_rule_parse_block(struct mgmt_connection *c, char *expr) {

	char *words[3]; 
	int wordcount = 0;

	char *str, *saveptr, *token;

	for (str = expr; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (token == NULL)
			break;
		if (strlen(token) == 0)
			continue;
		
		// there should not be more than 3 words
		if (wordcount >= 3) {
			mgmtsrv_send(c, "Could not parse \"%s\"\r\n", expr);
			return NULL;
		}

		words[wordcount] = token;
		wordcount++;
		
	}

	if (wordcount == 2) {
		mgmtsrv_send(c, "Could not parse \"%s\"\r\n", expr);
		return NULL;
	}

	if (wordcount == 1) {
		int layer = match_get_type(words[0]);
		if (layer == POM_ERR) 
			layer = match_register(words[0]);
		if (layer == POM_ERR) {
			mgmtsrv_send(c, "Unknown match \"%s\"\r\n", words[0]);
			return NULL;
		}
		struct rule_node *rn = malloc(sizeof(struct rule_node));
		bzero(rn, sizeof(struct rule_node));

		rn->layer = layer;
		return rn;
	}
	

	// wordcount is supposed to be 3 now
	char *field = strchr(words[0], '.');
	if (!field) {
		mgmtsrv_send(c, "Expression \"%s\" doesn't not contain a field specifier\r\n", words[0]);
		return NULL;
	}

	*field = 0;
	field++;
	int layer = match_get_type(words[0]);
	if (layer == POM_ERR)
		layer = match_register(words[0]);
	if (layer == POM_ERR) {
		mgmtsrv_send(c, "Unknown match \"\"\r\n", words[0]);
		return NULL;
	}
	
	struct match_param *param;
	param = match_alloc_param(layer, field);
	if (param == NULL) {
		mgmtsrv_send(c, "Unknown field \"%s\" for match \"%s\"\r\n", field, words[0]);
		return NULL;
	}

	param->op = ptype_get_op(param->value, words[1]);
	if (param->op == POM_ERR) {
		mgmtsrv_send(c, "Unknown or unsuported operation \"%s\" for field \"%s\" and match \"%s\"\r\n", words[1], field, words[0]);
		free(param);
		return NULL;
	}

	if (ptype_parse_val(param->value, words[2]) == POM_ERR) {
		mgmtsrv_send(c, "Unable to parse \"%s\" for field \"%s\" and match \"%s\"\r\n", words[2], field, words[0]);
		free(param);
		return NULL;
	}

	struct rule_node *rn = malloc(sizeof(struct rule_node));
	bzero(rn, sizeof(struct rule_node));
	rn->layer = layer;
	rn->match = param;
	return rn;

}

int mgmtcmd_set_rule_parse_branch(struct mgmt_connection *c, char *expr, struct rule_node **start, struct rule_node **end) {

	int stack_size = 0;
	int i, len;
	len = strlen(expr);
	
	int found = 0; // what operation was found
	int found_len = 0; // lenght of the string matched

	// let's see if there is a branch
	for (i = 0; i < len - 2; i++) {
		if (stack_size == 0 && expr[i] == 'o' && expr[i + 1] == 'r') {
			found = RULE_OP_OR;
			found_len = 2;
		}
		if (stack_size == 0 && expr[i] == 'a' && expr[i + 1] == 'n' && expr[i + 2] == 'd') {
			found = RULE_OP_AND;
			found_len = 3;
		}

		if (found) {
			if (i < 1 || i > len - found_len) {
				found = 0;
				continue;
			}
			if (expr[i - 1] != ')' && expr[i - 1] != ' ') {
				found = 0;
				continue;
			}

			if (expr[i + found_len] != ' ' && expr[i + found_len] != '(' && expr[i + found_len] != '!') {
				found = 0;
				continue;
			}

			expr[i] = 0;

			struct rule_node *my_start = malloc(sizeof(struct rule_node));
			bzero(my_start, sizeof(struct rule_node));

			struct rule_node *my_end = malloc(sizeof(struct rule_node));
			bzero(my_end, sizeof(struct rule_node));
			my_start->op = found;
			my_end->op = RULE_OP_TAIL;

			*start = my_start;
			*end = my_end;

			struct rule_node *the_end = NULL;
			mgmtcmd_set_rule_split(c, expr, &my_start->a, &the_end);
			the_end->a = my_end;
			mgmtcmd_set_rule_split(c, expr + i + found_len, &my_start->b, &the_end);
			the_end->a = my_end;

			return POM_OK;
		}
				

		if (expr[i] == '(') {
			stack_size++;
			continue;
		}

		if (expr[i] == ')') {
			stack_size--;
			if (stack_size < 0) {
				mgmtsrv_send(c, "Unmatched )\r\n");
				return POM_ERR;
			}
		}


	}



	int inv = 0; // should this match be inverted
	// first, trim this expr
	while(*expr == ' ')
		expr++;
	while (strlen(expr) > 0 && expr[strlen(expr) - 1] == ' ')
		expr[strlen(expr) - 1] = 0;

	if (expr[0] == '!') {
		inv = 1;
		expr++;
		while(*expr == ' ')
			expr++;
	}
	if (expr[0] == '(' && strlen(expr) > 0 && expr[strlen(expr) - 1] == ')') { // parenthesis at begining and end of block
		expr++;
		expr[strlen(expr) - 1] = 0;
		if (mgmtcmd_set_rule_split(c, expr, start, end) == POM_ERR)
			return POM_ERR;

		if (inv) {
			if ((*start)->op == 0) {
				mgmtsrv_send(c, "Unexpected \"!\"\r\n");
				return POM_ERR;
			}
			(*start)->op |= RULE_OP_NOT;
		}
		return POM_OK;
	}

	*start = mgmtcmd_set_rule_parse_block(c, expr);
	if (!*start)
		return POM_ERR;
	*end = *start;

	if (inv)
		(*start)->op |= RULE_OP_NOT;

	return POM_OK;
}


int mgmtcmd_set_rule_split(struct mgmt_connection *c, char *expr, struct rule_node **start, struct rule_node **end) {

	int pstart = 0;
	int stack_size = 0;
	int i, len;

	struct rule_node *my_start, **my_start_addr;
	my_start_addr = &my_start;

	*start = NULL;

	len = strlen(expr);
	for (i = 0; i < len; i++) {
		if (stack_size == 0 && expr[i] == '|') {
			expr[i] = 0;
			if (mgmtcmd_set_rule_parse_branch(c, expr + pstart, my_start_addr, end) == POM_ERR)
				return POM_ERR;
			if (!*start)
				*start = *my_start_addr;
			my_start_addr = &(*end)->a;

			pstart = i + 1;
		}
		if (expr[i] == '(') {
			stack_size++;
			continue;
		}
		
		if (expr[i] == ')') {
			stack_size--;
			if (stack_size < 0) {
				mgmtsrv_send(c, "Unmatched )\r\n");
				return POM_ERR;
			}
		}
	}

	if (stack_size > 0) {
		mgmtsrv_send(c, "Unmatched (\r\n");
		return POM_ERR;
	}

	// parse the last block
	if (mgmtcmd_set_rule_parse_branch(c, expr + pstart, my_start_addr, end))
		return POM_ERR;
	if (!*start)
		*start = *my_start_addr;


	return POM_OK;
}

int mgmtcmd_set_rule(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 2)
		return MGMT_USAGE;

	int rule_id;
	if (sscanf(argv[0], "%u", &rule_id) < 1)
		return MGMT_USAGE;

	struct rule_list *rl = main_config->rules;

	int i;
	for (i = 0; i < rule_id && rl; i++)
		rl = rl->next;

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	// first, let's reconstruct the whole rule
	int rule_len = 0;
	for (i = 1; i < argc; i++) {
		rule_len += strlen(argv[i]) + 1;
	}
	char *rule_str = malloc(rule_len + 1);
	bzero(rule_str, rule_len + 1);
	for (i = 1; i < argc; i++) {
		strcat(rule_str, argv[i]);
		strcat(rule_str, " ");
	}

	struct rule_node *start, *end;
	if (mgmtcmd_set_rule_split(c, rule_str, &start, &end) == POM_ERR) {
		node_destroy(start, 0);
		free(rule_str);
		return POM_OK;
	}

	free(rule_str);

	// rule parsed, let's replace it
	rl = main_config->rules;
	for (i = 0; i < rule_id && rl; i++)
		rl = rl->next;
	reader_process_lock();
	node_destroy(rl->node, 0);
	rl->node = start;
	reader_process_unlock();

	return POM_OK;
}

int mgmtcmd_show_input(struct mgmt_connection *c, int argc, char *argv[]) {

	mgmtsrv_send(c, "Current input : ");
	struct input* i = main_config->input;
	if (!i) {
		mgmtsrv_send(c, "none?!\r\n");
		return POM_OK;
	}
	mgmtsrv_send(c, input_get_name(i->type));
	mgmtsrv_send(c, ", mode ");
	mgmtsrv_send(c, i->mode->name);

	if (i->running)
		mgmtsrv_send(c, " (running)\r\n");
	else
		mgmtsrv_send(c, "\r\n");
	
	struct input_param *p = i->mode->params;
	while (p) {
		char buff[256];
		bzero(buff, sizeof(buff));
		ptype_print_val(p->value, buff, sizeof(buff));
		mgmtsrv_send(c, "  %s = %s %s\r\n", p->name, buff, p->value->unit);
		p = p->next;
	}


	return POM_OK;
}

int mgmtcmd_show_targets(struct mgmt_connection *c, int argc, char *argv[]) {


	struct rule_list *rl = main_config->rules;

	unsigned int rule_num = 0;

	while (rl) {
		mgmtsrv_send(c, "Rule %u", rule_num);
		if (!rl->enabled)
			mgmtsrv_send(c, " (disabled)");
		mgmtsrv_send(c, " : \r\n");

		struct target *t = rl->target;

		while (t) {
			mgmtsrv_send(c, "  %s", target_get_name(t->type));
			if (t->mode) {
				mgmtsrv_send(c, ", mode %s\r\n", t->mode->name);
				struct target_param_reg *pr = t->mode->params;
				while (pr) {
					char buff[256];
					bzero(buff, sizeof(buff));
					struct ptype *value = target_get_param_value(t, pr->name);
					ptype_print_val(value , buff, sizeof(buff));
					mgmtsrv_send(c, "    %s = %s %s\r\n", pr->name, buff, value->unit);
					pr = pr->next;
				}

			}
			mgmtsrv_send(c, "\r\n");
			t = t->next;
		}

		rl = rl->next;
		rule_num++;
	}

	return POM_OK;
}

int mgmtcmd_disable_rule(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	int rule_id;
	if (sscanf(argv[0], "%u", &rule_id) < 1)
		return MGMT_USAGE;

	struct rule_list *rl = main_config->rules;

	int i;
	for (i = 0; i < rule_id && rl; i++)
		rl = rl->next;

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	if (!rl->enabled) {
		mgmtsrv_send(c, "Rule already disabled\n");
		return POM_OK;
	}

	rl->enabled = 0;

	return POM_OK;

}

int mgmtcmd_enable_rule(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	int rule_id;
	if (sscanf(argv[0], "%u", &rule_id) < 1)
		return MGMT_USAGE;

	struct rule_list *rl = main_config->rules;

	int i;
	for (i = 0; i < rule_id && rl; i++)
		rl = rl->next;

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	if (rl->enabled) {
		mgmtsrv_send(c, "Rule already enabled\n");
		return POM_OK;
	}

	rl->enabled = 1;

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

int mgmtcmd_start_input(struct mgmt_connection *c, int argc, char *argv[]) {


	if (rbuf->state != rb_state_closed) {
		mgmtsrv_send(c, "Input already started\r\n");
		return POM_OK;
	}

	start_input(rbuf);
	return POM_OK;

}

int mgmtcmd_stop_input(struct mgmt_connection *c, int argc, char *argv[]) {


	if (rbuf->state == rb_state_closed) {
		mgmtsrv_send(c, "Input already stopped\r\n");
		return POM_OK;
	}

	stop_input(rbuf);
	return POM_OK;

}

int mgmtcmd_write_config(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		config_write(main_config, NULL);
	else
		config_write(main_config, argv[0]);

	return POM_OK;

}
