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

#define MGMT_RULE_COMMANDS_NUM 8

static struct mgmt_command mgmt_rule_commands[MGMT_RULE_COMMANDS_NUM] = {

	{
		.words = { "show", "rules", NULL },
		.help = "Display all the configured rules",
		.callback_func = mgmtcmd_show_rules,
		.completion = mgmt_show_rules_completion,
		.usage = "show rules [tree | flat]",
	},
	
	{
		.words = { "set", "rule", NULL },
		.help = "Change a rule",
		.callback_func = mgmtcmd_set_rule,
		.completion = mgmtcmd_rule_id2_completion,
		.usage = "set rule <rule_id> <rule>",
	},

	{
		.words = { "disable", "rule", NULL },
		.help = "Disable a rule",
		.callback_func = mgmtcmd_disable_rule,
		.completion = mgmtcmd_rule_id2_completion,
		.usage = "disable rule <rule_id>",
	},

	{
		.words = { "enable", "rule", NULL },
		.help = "Enable a rule",
		.callback_func = mgmtcmd_enable_rule,
		.completion = mgmtcmd_rule_id2_completion,
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
		.help = "Remove a rule",
		.callback_func = mgmtcmd_remove_rule,
		.completion = mgmtcmd_rule_id2_completion,
		.usage = "remove rule <rule_id>",
	},

	{
		.words = { "set", "rule", "description", NULL },
		.help = "set a description on a rule",
		.callback_func = mgmtcmd_set_rule_descr,
		.completion = mgmtcmd_rule_id3_completion,
		.usage = "set rule description <rule_id> <descr>",
	},

	{
		.words = { "unset", "rule", "description", NULL },
		.help = "Unset the description on a rule",
		.callback_func = mgmtcmd_unset_rule_descr,
		.completion = mgmtcmd_rule_id3_completion,
		.usage = "unset rule description <rule_id>",
	},
};

struct mgmt_command_arg* mgmtcmd_rule_id2_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;
	
	return mgmtcmd_rule_id_completion();
}
	
struct mgmt_command_arg* mgmtcmd_rule_id3_completion(int argc, char *argv[]) {

	if (argc != 3)
		return NULL;
	
	return mgmtcmd_rule_id_completion();
}

struct mgmt_command_arg* mgmtcmd_rule_id_completion() {
	main_config_rules_lock(0);
	struct rule_list *rl;
	int count = 0;
	for (rl = main_config->rules; rl; rl = rl->next)
		count++;
	main_config_rules_unlock();

	return mgmtcmd_completion_int_range(0, count);
	
}

int mgmtcmd_rule_register_all() {

	int i;


	for (i = 0; i < MGMT_RULE_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_rule_commands[i]);
	}

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


	main_config_rules_lock(0);

	struct rule_list *rl = main_config->rules;

	if (!rl) {
		main_config_rules_unlock();
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
		if (rl->description)
			mgmtsrv_send(c, "  // %s\r\n", rl->description);

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
				char buffer[4096];
				memset(buffer, 0, sizeof(buffer));
				rule_print_flat(rl->node, NULL, buffer, sizeof(buffer) - 1);
				mgmtsrv_send(c, "%s\r\n", buffer);
			} else  {
				main_config_rules_unlock();
				return MGMT_USAGE;
			}
		} else {
			char buffer[4096];
			memset(buffer, 0, sizeof(buffer));
			rule_print_flat(rl->node, NULL, buffer, sizeof(buffer) - 1);
			mgmtsrv_send(c, "%s\r\n", buffer);
		}
		mgmtsrv_send(c, "\r\n");

		rl = rl->next;
		rule_num++;
	}

	main_config_rules_unlock();

	return POM_OK;
}

struct mgmt_command_arg* mgmt_show_rules_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg* res = NULL;

	res = malloc(sizeof(struct mgmt_command_arg));
	memset(res, 0, sizeof(struct mgmt_command_arg));
	char *flat = "flat";
	res->word = malloc(strlen(flat) + 1);
	strcpy(res->word, flat);

	struct mgmt_command_arg* tmp = NULL;
	tmp = malloc(sizeof(struct mgmt_command_arg));
	memset(tmp, 0, sizeof(struct mgmt_command_arg));
	char *tree = "tree";
	tmp->word = malloc(strlen(tree) + 1);
	strcpy(tmp->word, tree);

	res->next = tmp;

	return res;

}

int mgmtcmd_set_rule(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 2)
		return MGMT_USAGE;

	unsigned int rule_id;
	if (sscanf(argv[0], "%u", &rule_id) < 1)
		return MGMT_USAGE;

	main_config_rules_lock(0);
	struct rule_list *rl = main_config->rules;

	unsigned int i;
	for (i = 0; i < rule_id && rl; i++)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}
	main_config_rules_unlock();

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
	char errbuff[256];
	memset(errbuff, 0, sizeof(errbuff));
	if (rule_parse(rule_str, &start, &end, errbuff, sizeof(errbuff) - 1) == POM_ERR) {
		mgmtsrv_send(c, "Unable to parse the rule : %s\r\n", errbuff);
		node_destroy(start, 0);
		free(rule_str);
		return POM_OK;
	}

	free(rule_str);

	// rule parsed, let's replace it
	main_config_rules_lock(1);
	node_destroy(rl->node, 0);
	rl->node = start;
	main_config->rules_serial++;
	rl->serial++;
	main_config_rules_unlock();

	return POM_OK;
}

int mgmtcmd_disable_rule(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	main_config_rules_lock(1);
	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
	} else if (!rl->enabled) {
		mgmtsrv_send(c, "Rule already disabled\n");
	} else {
		rl->enabled = 0;
		main_config->rules_serial++;
		rl->serial++;
	}
	main_config_rules_unlock();

	return POM_OK;

}

int mgmtcmd_enable_rule(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	main_config_rules_lock(1);
	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
	} else 	if (rl->enabled) {
		mgmtsrv_send(c, "Rule already enabled\n");
	} else {
		rl->enabled = 1;
		main_config->rules_serial++;
		rl->serial++;
	}
	main_config_rules_unlock();

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
	char errbuff[256];
	memset(errbuff, 0, sizeof(errbuff));
	if (rule_parse(rule_str, &start, &end, errbuff, sizeof(errbuff) - 1) == POM_ERR) {
		mgmtsrv_send(c, "Unable to parse the rule : %s\r\n", errbuff);
		node_destroy(start, 0);
		free(rule_str);
		return POM_OK;
	}

	free(rule_str);

	// rule parsed, let's add it

	struct rule_list *rl;
	rl = malloc(sizeof(struct rule_list));
	memset(rl, 0, sizeof(struct rule_list));

	main_config_rules_lock(1);
	rl->uid = get_uid();
	main_config->rules_serial++;

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
	rl->byte_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN_1024;

	main_config_rules_unlock();
	
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

	main_config_rules_lock(1);

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

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
		target_lock_instance(tmpt, 1);

		if (tmpt->started)
			target_close(tmpt);

		target_cleanup_module(tmpt);
		
	}

	ptype_cleanup(rl->pkt_cnt);
	ptype_cleanup(rl->byte_cnt);
	free(rl);

	main_config->rules_serial++;
	main_config_rules_unlock();

	mgmtsrv_send(c, "Rule removed\r\n");

	return POM_OK;

}

int mgmtcmd_set_rule_descr(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 2)
		return MGMT_USAGE;

	main_config_rules_lock(1);
	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	if (rl->description)
		free(rl->description);

	// first, let's reconstruct the whole description
	int rule_descr_len = 0, i;
	for (i = 1; i < argc; i++) {
		rule_descr_len += strlen(argv[i]) + 1;
	}
	char *rule_descr = malloc(rule_descr_len + 1);
	memset(rule_descr, 0, rule_descr_len + 1);
	for (i = 1; i < argc; i++) {
		strcat(rule_descr, argv[i]);
		strcat(rule_descr, " ");
	}
	rule_descr[strlen(rule_descr) - 1] = 0;
	rl->description = rule_descr;

	main_config->rules_serial++;
	rl->serial++;
	main_config_rules_unlock();

	return POM_OK;
}


int mgmtcmd_unset_rule_descr(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	main_config_rules_lock(1);
	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	if (rl->description) {
		free(rl->description);
		rl->description = NULL;
		main_config->rules_serial++;
		rl->serial++;
	} else {
		mgmtsrv_send(c, "Rule %s has no description\r\n", argv[0]);
	}
	main_config_rules_unlock();

	return POM_OK;
}

