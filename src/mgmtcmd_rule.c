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


#include "mgmtcmd_rule.h"

#include "ptype_uint64.h"

#define MGMT_RULE_COMMANDS_NUM 6

struct mgmt_command mgmt_rule_commands[MGMT_RULE_COMMANDS_NUM] = {

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
		.usage = "set rule <rule_id> <rule>",
	},

	{
		.words = { "disable", "rule", NULL },
		.help = "Disable a rule",
		.callback_func = mgmtcmd_disable_rule,
		.usage = "disable rule <rule_id>",
	},

	{
		.words = { "enable", "rule", NULL },
		.help = "Enable a rule",
		.callback_func = mgmtcmd_enable_rule,
		.usage = "enable rule <rule_id>",
	},

	{
		.words = { "add", "rule", NULL },
		.help = "Add a rule",
		.callback_func = mgmtcmd_add_rule,
		.usage = "add rule <rule>",
	},

	{
		.words = { "remove", "rule", NULL },
		.help = "remove a rule",
		.callback_func = mgmtcmd_remove_rule,
		.usage = "remove rule <rule_id>",
	},

};

int mgmtcmd_rule_register_all() {

	int i;


	for (i = 0; i < MGMT_RULE_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_rule_commands[i]);
	}

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

					struct match_field_reg *field = match_get_field(n->layer, n->match->id);
					mgmtsrv_send(c, ".%s %s %s" , field->name, ptype_get_op_sign(n->match->op), buff);

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

			mgmtcmd_show_rule_print_node_flat(c, n->a, new_last);
			if (n->op & RULE_OP_OR)
				mgmtsrv_send(c, " or ");
			else if (n->op & RULE_OP_AND)
				mgmtsrv_send(c, " and ");

			mgmtcmd_show_rule_print_node_flat(c, n->b, new_last);

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

					struct match_field_reg *field = match_get_field(n->layer, n->match->id);
					mgmtsrv_send(c, ".%s %s %s" , field->name, ptype_get_op_sign(n->match->op), buff);

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
			if (n->op & RULE_OP_OR)
				mgmtsrv_send(c, "or --- ");
			else if (n->op & RULE_OP_AND)
				mgmtsrv_send(c, "and -- ");

			
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

	if (!rl) {
		mgmtsrv_send(c, "No rules\r\n");
		return POM_OK;
	}


	unsigned int rule_num = 0;

	while (rl) {
		char pkts[16], bytes[16];
		ptype_print_val(rl->pkt_cnt, pkts, sizeof(pkts));
		ptype_print_val(rl->byte_cnt, bytes, sizeof(bytes));
		mgmtsrv_send(c, "Rule %u (%s %s, %s %s)", rule_num, pkts, rl->pkt_cnt->unit, bytes, rl->byte_cnt->unit);
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
			mgmtcmd_show_rule_print_node_flat(c, rl->node, NULL);

		mgmtsrv_send(c, "\r\n");

		rl = rl->next;
		rule_num++;
	}

	return POM_OK;
}

struct rule_node *mgmtcmd_set_rule_parse_block(struct mgmt_connection *c, char *expr) {

	char *words[3]; 
	int wordcount = 0;

	char *str, *token, *saveptr = NULL;

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
		memset(rn, 0, sizeof(struct rule_node));

		rn->layer = layer;
		match_refcount_inc(layer);
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
	
	struct match_field *param;
	param = match_alloc_field(layer, field);
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
	memset(rn, 0, sizeof(struct rule_node));
	rn->layer = layer;
	rn->match = param;
	match_refcount_inc(layer);
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
			memset(my_start, 0, sizeof(struct rule_node));

			struct rule_node *my_end = malloc(sizeof(struct rule_node));
			memset(my_end, 0, sizeof(struct rule_node));
			my_start->op = found;
			my_end->op = RULE_OP_TAIL;

			*start = my_start;
			*end = my_end;

			struct rule_node *the_end = NULL;
			if (mgmtcmd_set_rule_split(c, expr, &my_start->a, &the_end) == POM_ERR)
				return POM_ERR;
			if (!the_end)
				return POM_ERR;

			the_end->a = my_end;
			if (mgmtcmd_set_rule_split(c, expr + i + found_len, &my_start->b, &the_end) == POM_ERR)
				return POM_ERR;
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
			if ((*start)->b){
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

	if (inv) {
		if ((*start)->b) {
			mgmtsrv_send(c, "Cannot use '!' with or/and operation\r\n");
			return POM_ERR;
		} else
			(*start)->op |= RULE_OP_NOT;
	}
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
	if (mgmtcmd_set_rule_parse_branch(c, expr + pstart, my_start_addr, end) == POM_ERR)
		return POM_ERR;
	if (!*start)
		*start = *my_start_addr;


	return POM_OK;
}

int mgmtcmd_set_rule(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 2)
		return MGMT_USAGE;

	unsigned int rule_id;
	if (sscanf(argv[0], "%u", &rule_id) < 1)
		return MGMT_USAGE;

	struct rule_list *rl = main_config->rules;

	unsigned int i;
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
	memset(rule_str, 0, rule_len + 1);
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

int mgmtcmd_disable_rule(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

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

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

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

int mgmtcmd_add_rule(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	// reconstruct the rule
	int rule_len = 0, i;
	for (i = 0; i < argc; i++) {
		rule_len += strlen(argv[i]) + 1;
	}
	char *rule_str = malloc(rule_len + 1);
	memset(rule_str, 0, rule_len + 1);
	for (i = 0; i < argc; i++) {
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

	// rule parsed, let's add it

	struct rule_list *rl;
	rl = malloc(sizeof(struct rule_list));

	memset(rl, 0, sizeof(struct rule_list));

	reader_process_lock();
	
	int rule_id = 0;

	if (!main_config->rules) {
		main_config->rules = rl;
	} else {
		rule_id = 1;
		struct rule_list *tmprl = main_config->rules;
		while (tmprl->next) {
			tmprl = tmprl->next;
			rule_id++;
		}
		tmprl->next = rl;
		rl->prev = tmprl;
	}
	
	rl->node = start;
	rl->pkt_cnt = ptype_alloc("uint64", "pkts");
	rl->pkt_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN;
	rl->byte_cnt = ptype_alloc("uint64", "bytes");
	rl->byte_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN;

	reader_process_unlock();
	
	mgmtsrv_send(c, "Added rule with id %u\r\n", rule_id);

	return POM_OK;
}

struct rule_list *mgmtcmd_get_rule(char *rule) {

	unsigned int rule_id;
	if (sscanf(rule, "%u", &rule_id) < 1)
		return NULL;

	struct rule_list *rl = main_config->rules;

	unsigned int i;
	for (i = 0; i < rule_id && rl; i++)
		rl = rl->next;

	return rl;

}

int mgmtcmd_remove_rule(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	reader_process_lock();

	node_destroy(rl->node, 0);

	if (rl->prev)
		rl->prev->next = rl->next;
	else
		main_config->rules = rl->next;

	if (rl->next)
		rl->next->prev = rl->prev;

	while (rl->target) {

		struct target *tmpt = rl->target;
		rl->target = rl->target->next;

		if (tmpt->started)
			target_close(tmpt);

		target_cleanup_module(tmpt);
		
	}

	ptype_cleanup(rl->pkt_cnt);
	ptype_cleanup(rl->byte_cnt);
	free(rl);

	reader_process_unlock();

	mgmtsrv_send(c, "Rule removed\r\n");

	return POM_OK;

}
