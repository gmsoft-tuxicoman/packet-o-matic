/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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
#include "xmlrpcsrv.h"
#include "xmlrpccmd_rules.h"
#include "main.h"
#include "rules.h"

#include "ptype_uint64.h"

#define XMLRPC_RULES_COMMANDS_NUM 7

static struct xmlrpc_command xmlrpc_rules_commands[XMLRPC_RULES_COMMANDS_NUM] = { 

	{
		.name = "rules.get",
		.callback_func = xmlrpccmd_get_rules,
		.signature = "A:,n:",
		.help = "Get all the rules",
	},

	{
		.name = "rules.getSerial",
		.callback_func = xmlrpccmd_get_rules_serial,
		.signature = "i:",
		.help = "Get the rule serial number",
	},

	{
		.name = "rules.add",
		.callback_func = xmlrpccmd_add_rule,
		.signature = "i:i",
		.help = "Add a rule and get it's UID",
	},

	{
		.name = "rules.set",
		.callback_func = xmlrpccmd_set_rule,
		.signature = "i:is",
		.help = "Set a rule and get it's new UID",
	},

	{
		.name = "rules.remove",
		.callback_func = xmlrpccmd_remove_rule,
		.signature = "n:",
		.help = "Remove a rule given its UID",
	},

	{
		.name = "rules.enable",
		.callback_func = xmlrpccmd_enable_rule,
		.signature = "i:i",
		.help = "Enable a rule and get its new UID",
	},

	{
		.name = "rules.disable",
		.callback_func = xmlrpccmd_disable_rule,
		.signature = "i:i",
		.help = "Disable a rule and get its new UID",
	},
};

int xmlrpccmd_rules_register_all() {

	int i;

	for (i = 0; i < XMLRPC_RULES_COMMANDS_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpc_rules_commands[i]) == POM_ERR)
			return POM_ERR;

	}

	return POM_OK;
}

xmlrpc_value *xmlrpccmd_get_rules(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	main_config_rules_lock(0);

	struct rule_list* rl = main_config->rules;

	if (!rl) {
		main_config_rules_unlock();
		return xmlrpc_nil_new(envP);
	}

	xmlrpc_value *rules = xmlrpc_array_new(envP);
	if (envP->fault_occurred) {
		main_config_rules_unlock();
		return NULL;
	}

	while (rl) {
		char buff[2048];
		memset(buff, 0, sizeof(buff));
		if (rule_print_flat(rl->node, NULL, buff, sizeof(buff) - 1) == POM_ERR) {
			main_config_rules_unlock();
			xmlrpc_faultf(envP, "Error while computing string representation of the rule");
			return NULL;
		}
		xmlrpc_value *rule = xmlrpc_build_value(envP, "{s:s,s:b,s:i}",
					"rule", buff,
					"enabled", rl->enabled,
					"uid", rl->uid);
		xmlrpc_array_append_item(envP, rules, rule);
		xmlrpc_DECREF(rule);
		rl = rl->next;
	}



	if (envP->fault_occurred) {
		main_config_rules_unlock();
		return NULL;
	}

	main_config_rules_unlock();

	return rules;
}

xmlrpc_value *xmlrpccmd_get_rules_serial(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	main_config_rules_lock(0);
	uint32_t serial = main_config->rules_serial;
	main_config_rules_unlock();

	return xmlrpc_int_new(envP, serial);

}

xmlrpc_value *xmlrpccmd_add_rule(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	char *rule_str;
	xmlrpc_decompose_value(envP, paramArrayP, "(s)", &rule_str);

	if (envP->fault_occurred)
		return NULL;
	

	char errbuff[256];
	memset(errbuff, 0, sizeof(errbuff));

	struct rule_node *start, *end;

	if (rule_parse(rule_str, &start, &end, errbuff, sizeof(errbuff) - 1) == POM_ERR) {
		free(rule_str);
		xmlrpc_faultf(envP, "Error while parsing the rule : %s", errbuff);
		return NULL;
	}
	free(rule_str);

	// rule parsed, let's add it

	struct rule_list *rl;
	rl = malloc(sizeof(struct rule_list));
	memset(rl, 0, sizeof(struct rule_list));

	main_config_rules_lock(1);
	rule_update(rl, main_config->rules, &main_config->rules_serial);

	if (!main_config->rules) {
		main_config->rules = rl;
	} else {
		struct rule_list *tmprl = main_config->rules;
		while (tmprl->next) {
			tmprl = tmprl->next;
		}
		tmprl->next = rl;
		rl->prev = tmprl;
	}
	
	rl->node = start;
	rl->pkt_cnt = ptype_alloc("uint64", "pkts");
	rl->pkt_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN;
	rl->byte_cnt = ptype_alloc("uint64", "bytes");
	rl->byte_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN;

	main_config_rules_unlock();

	return xmlrpc_int_new(envP, rl->uid);

}

xmlrpc_value *xmlrpccmd_set_rule(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t rule_id;
	char *rule_str;
	xmlrpc_decompose_value(envP, paramArrayP, "(is)", &rule_id, &rule_str);

	if (envP->fault_occurred)
		return NULL;

	main_config_rules_lock(0);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		free(rule_str);
		xmlrpc_faultf(envP, "Rule not found");
		return NULL;
	}
	main_config_rules_unlock();

	char errbuff[256];
	memset(errbuff, 0, sizeof(errbuff));

	struct rule_node *start, *end;

	if (rule_parse(rule_str, &start, &end, errbuff, sizeof(errbuff) - 1) == POM_ERR) {
		free(rule_str);
		xmlrpc_faultf(envP, "Error while parsing the rule : %s", errbuff);
		return NULL;
	}

	free(rule_str);

	main_config_rules_lock(1);

	node_destroy(rl->node, 0);
	rl->node = start;
	rule_update(rl, main_config->rules, &main_config->rules_serial);

	main_config_rules_unlock();

	return xmlrpc_int_new(envP, rl->uid);

}

xmlrpc_value *xmlrpccmd_remove_rule(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t rule_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &rule_id);

	if (envP->fault_occurred)
		return NULL;

	main_config_rules_lock(1);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		xmlrpc_faultf(envP, "Rule not found");
		main_config_rules_unlock();
		return NULL;
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

		if (tmpt->started)
			target_close(tmpt);

		target_cleanup_module(tmpt);
		
	}

	ptype_cleanup(rl->pkt_cnt);
	ptype_cleanup(rl->byte_cnt);
	free(rl);

	main_config_rules_unlock();

	return xmlrpc_nil_new(envP);

}

xmlrpc_value *xmlrpccmd_enable_rule(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t rule_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &rule_id);

	if (envP->fault_occurred)
		return NULL;

	main_config_rules_lock(1);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		return NULL;
	} else if (rl->enabled) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule already enabled");
		return NULL;	
	}

	rl->enabled = 1;

	rule_update(rl, main_config->rules, &main_config->rules_serial);
	main_config_rules_unlock();

	return xmlrpc_int_new(envP, rl->uid);

}

xmlrpc_value *xmlrpccmd_disable_rule(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	uint32_t rule_id;
	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &rule_id);

	if (envP->fault_occurred)
		return NULL;

	main_config_rules_lock(1);

	struct rule_list *rl = main_config->rules;
	while (rl && rl->uid != rule_id)
		rl = rl->next;

	if (!rl) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule not found");
		return NULL;
	} else if (!rl->enabled) {
		main_config_rules_unlock();
		xmlrpc_faultf(envP, "Rule already disabled");
		return NULL;	
	}

	rl->enabled = 0;

	rule_update(rl, main_config->rules, &main_config->rules_serial);
	main_config_rules_unlock();

	return xmlrpc_int_new(envP, rl->uid);

}
