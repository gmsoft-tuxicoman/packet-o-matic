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



#include "mgmtcmd_target.h"
#include "mgmtcmd_rule.h"
#include "target.h"
#include "perf.h"


#define MGMT_TARGET_COMMANDS_NUM 13

static struct mgmt_command mgmt_target_commands[MGMT_TARGET_COMMANDS_NUM] = {

	{
		.words = { "target", "show", NULL },
		.help = "Display informations about the targets in every rule",
		.callback_func = mgmtcmd_target_show,
	},

	{
		.words = { "target", "start", NULL },
		.help = "Start a target",
		.callback_func = mgmtcmd_target_start,
		.usage = "target start <rule_id> <target_id>",
		.completion = mgmtcmd_target_completion_id2,
	},

	{
		.words = { "target", "stop", NULL },
		.help = "Stop a target",
		.callback_func = mgmtcmd_target_stop,
		.usage = "target stop <rule_id> <target_id>",
		.completion = mgmtcmd_target_completion_id2,
	},

	{
		.words = { "target", "add", NULL },
		.help = "Add a target to a rule",
		.callback_func = mgmtcmd_target_add,
		.usage = "target add <rule_id> <target>",
		.completion = mgmtcmd_target_name_completion,
	},

	{
		.words = { "target", "remove", NULL },
		.help = "Remove a target from a rule",
		.callback_func = mgmtcmd_target_remove,
		.usage = "target remove <rule_id> <target_id>",
		.completion = mgmtcmd_target_completion_id2,
	},

	{
		.words = { "target", "parameter", "set", NULL },
		.help = "Change the value of a target parameter",
		.callback_func = mgmtcmd_target_parameter_set,
		.usage = "target parameter set <rule_id> <target_id> <parameter> <value>",
		.completion = mgmtcmd_target_parameter_set_completion,
	},

	{
		.words = { "target", "parameter", "reset", NULL },
		.help = "Reset a target parameter to its default value",
		.callback_func = mgmtcmd_target_parameter_reset,
		.usage = "target parameter reset <rule_id> <target_id> <parameter>",
		.completion = mgmtcmd_target_parameter_set_completion,
	},

	{
		.words = { "target", "description", "set",  NULL },
		.help = "Set a description on a target",
		.callback_func = mgmtcmd_target_description_set,
		.completion = mgmtcmd_target_completion_id3,
		.usage = "target description set <rule_id> <target_id> <descr>",
	},

	{
		.words = { "target", "description", "unset", NULL },
		.help = "Unset the description of a target",
		.callback_func = mgmtcmd_target_description_unset,
		.completion = mgmtcmd_target_completion_id3,
		.usage = "target description unset <rule_id> <target_id>",
	},

	{
		.words = { "target", "mode", "set", NULL },
		.help = "Change the mode of a target",
		.callback_func = mgmtcmd_target_mode_set,
		.usage = "target mode set <rule_id> <target_id> <mode>",
		.completion = mgmtcmd_target_mode_set_completion,
	},

	{
		.words = { "target", "help", NULL },
		.help = "Get help for targets",
		.usage = "target help [target]",
		.callback_func = mgmtcmd_target_help,
		.completion = mgmtcmd_target_avail_completion,
	},

	{
		.words = { "target", "load", NULL },
		.help = "Load a target module",
		.usage = "target load <target>",
		.callback_func = mgmtcmd_target_load,
		.completion = mgmtcmd_target_avail_completion,
	},

	{
		.words = { "target", "unload", NULL },
		.help = "Unload a target module",
		.usage = "target unload <target>",
		.callback_func = mgmtcmd_target_unload,
		.completion = mgmtcmd_target_unload_completion,
	},
};

int mgmtcmd_target_register_all() {

	int i;

	for (i = 0; i < MGMT_TARGET_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_target_commands[i]);
	}

	return POM_OK;
}

struct mgmt_command_arg *mgmctcmd_target_id_completion(int argc, char *argv[], int pos) {

	struct mgmt_command_arg *res = NULL;

	if (pos == 0) {
		struct rule_list *rl;
		int count = 0;
		main_config_rules_lock(0);
		for (rl = main_config->rules; rl; rl = rl->next)
			count++;
		main_config_rules_unlock();
		res = mgmtcmd_completion_int_range(0, count);
	} else if (pos == 1) {
		struct rule_list *rl;
		int i = 0;
		int rule_id = -1;
		if (sscanf(argv[argc - 1], "%u", &rule_id) != 1)
			return NULL;
		main_config_rules_lock(0);
		for (rl = main_config->rules; rl && i < rule_id; rl = rl->next)
			i++;

		if (!rl) // No such rule
			return res;

		struct target *t = rl->target;
		int count = 0;
		for (t = rl->target; t; t = t->next)
			count++;
		main_config_rules_unlock();
		res = mgmtcmd_completion_int_range(0, count);

	}

	return res;
}

struct mgmt_command_arg *mgmtcmd_target_completion_id2(int argc, char *argv[]) {

	return mgmctcmd_target_id_completion(argc, argv, argc - 2);

}

struct mgmt_command_arg *mgmtcmd_target_completion_id3(int argc, char *argv[]) {

	return mgmctcmd_target_id_completion(argc, argv, argc - 3);

}

int mgmtcmd_target_show(struct mgmt_connection *c, int argc, char *argv[]) {

	main_config_rules_lock(0);

	struct rule_list *rl = main_config->rules;

	unsigned int rule_num = 0, target_num;

	while (rl) {
		char pkts[32], bytes[32], uptime[64];
		perf_item_val_get_human(rl->perf_pkts, pkts, sizeof(pkts) - 1);
		perf_item_val_get_human_1024(rl->perf_bytes, bytes, sizeof(bytes) - 1);
		perf_item_val_get_human(rl->perf_uptime, uptime, sizeof(uptime) - 1);
		mgmtsrv_send(c, "Rule %u : targets (%s packets, %s bytes, up %s)", rule_num, pkts, bytes, uptime);
		if (!rl->enabled)
			mgmtsrv_send(c, " (disabled)");
		mgmtsrv_send(c, " : \r\n");

		struct target *t = rl->target;

		target_num = 0;

		while (t) {
			target_lock_instance(t, 0);
			mgmtsrv_send(c, "   %u) %s", target_num, target_get_name(t->type));
			if (t->mode) {
				perf_item_val_get_human(t->perf_pkts, pkts, sizeof(pkts) - 1);
				perf_item_val_get_human_1024(t->perf_bytes, bytes, sizeof(bytes) - 1);
				perf_item_val_get_human(t->perf_uptime, uptime, sizeof(uptime) - 1);
				
				mgmtsrv_send(c, ", mode %s (%s packets, %s bytes, up %s)", t->mode->name, pkts, bytes, uptime);
				if (!t->started)
					mgmtsrv_send(c, " (stopped)");
				mgmtsrv_send(c, "\r\n");
				if (t->description)
					mgmtsrv_send(c, "        // %s\r\n", t->description);
				struct target_param_reg *pr = t->mode->params;
				while (pr) {
					char buff[256];
					memset(buff, 0, sizeof(buff));
					struct ptype *value = target_get_param_value(t, pr->name);
					ptype_print_val(value , buff, sizeof(buff));
					mgmtsrv_send(c, "        %s = %s %s\r\n", pr->name, buff, value->unit);
					pr = pr->next;
				}

			} else {
				if (!t->started)
					mgmtsrv_send(c, " (stopped)");
			}
			target_unlock_instance(t);
			mgmtsrv_send(c, "\r\n");
			t = t->next;
			target_num++;
		}

		rl = rl->next;
		rule_num++;
	}

	main_config_rules_unlock();

	return POM_OK;
}

int mgmtcmd_target_start(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;


	main_config_rules_lock(0);
	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	struct target *t = mgmtcmd_get_target(rl, argv[1]);
	main_config_rules_unlock();

	if (!t) {
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}

	target_lock_instance(t, 1);
	if (t->started) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "Target already started\r\n");
		return POM_OK;
	}

	if (target_open(t) != POM_OK) 
		mgmtsrv_send(c, "Error while starting the target\r\n");
	
	target_unlock_instance(t);

	return POM_OK;

}

int mgmtcmd_target_stop(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	main_config_rules_lock(0);

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	main_config_rules_unlock();

	if (!t) {
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}
	
	target_lock_instance(t, 1);
	if (!t->started) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "Target already stopped\r\n");
		return POM_OK;
	}

	if (target_close(t) != POM_OK)
		mgmtsrv_send(c, "Error while stopping the target\r\n");
	
	target_unlock_instance(t);

	return POM_OK;

}

int mgmtcmd_target_add(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	main_config_rules_lock(1);

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}
	target_lock(1);
	int target_type = target_register(argv[1]);

	if (target_type == POM_ERR) {
		target_unlock();
		main_config_rules_unlock();
		mgmtsrv_send(c, "Target %s not found\r\n", argv[1]);
		return POM_OK;
	}
	
	struct target *t = target_alloc(target_type);
	target_unlock();
	if (!t) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Error while allocating the target !!!\r\n");
		return POM_ERR;
	}

	int target_id = 0;

	// add the target at the end
	if (!rl->target) 
		rl->target = t;
	else {
		target_id = 1;
		struct target *tmpt = rl->target;
		while (tmpt->next) {
			tmpt = tmpt->next;
			target_id++;
		}
		tmpt->next = t;
		t->prev = tmpt;
	}

	t->parent_serial = &rl->target_serial;
	rl->target_serial++;
	main_config->target_serial++;

	main_config_rules_unlock();

	mgmtsrv_send(c, "Added target with id %u to rule %s\r\n", target_id, argv[0]);

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_target_name_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc == 2) {
		res = mgmctcmd_target_id_completion(argc, argv, 0);
	} else if (argc == 3) {
		res = mgmtcmd_list_modules("target");
	}
	return res;
}

struct target *mgmtcmd_get_target(struct rule_list *rl, char *target) {

	unsigned int target_id, i;
	if (sscanf(target, "%u", &target_id) < 1)
		return NULL;

	struct target *t = rl->target;

	for (i = 0; i < target_id && t; i++)
		t = t->next;

	return t;

}

int mgmtcmd_target_remove(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	main_config_rules_lock(1);

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}
	
	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	if (!t) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}
	target_lock_instance(t, 1);

	if (t->started) {
		target_close(t);
	}

	rl->target_serial++;
	main_config->target_serial++;

	if (t->prev)
		t->prev->next = t->next;
	else
		rl->target = t-> next;
	
	if (t->next)
		t->next->prev = t->prev;

	target_cleanup_module(t);

	main_config_rules_unlock();

	mgmtsrv_send(c, "Target removed\r\n");

	return POM_OK;

}

int mgmtcmd_target_parameter_set(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 4)
		return MGMT_USAGE;

	main_config_rules_lock(0);

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	target_lock(0);
	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	main_config_rules_unlock();

	if (!t) {
		target_unlock();
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}

	target_lock_instance(t, 1);
	target_unlock();

	if (t->started) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "Target must be stopped to change a parameter\r\n");
		return POM_OK;
	}
	

	struct ptype *value = target_get_param_value(t, argv[2]);
	if (!value) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "No parameter %s for target %s\r\n", argv[2], target_get_name(t->type));
		return POM_OK;
	}



	// first, let's reconstruct the whole parameter
	int i, param_len = 0;
	for (i = 1; i < argc; i++) {
		param_len += strlen(argv[i]) + 1;
	}
	char *param_str = malloc(param_len + 1);
	memset(param_str, 0, param_len + 1);
	for (i = 3; i < argc; i++) {
		strcat(param_str, argv[i]);
		if (i < argc - 1)
			strcat(param_str, " ");
	}

	if (ptype_parse_val(value, param_str) == POM_ERR) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "Unable to parse \"%s\" for parameter %s\r\n", param_str, argv[2]);
		free(param_str);
		return POM_OK;
	}
	free(param_str);

	main_config->target_serial++;
	rl->target_serial++;
	t->serial++;
	target_unlock_instance(t);

	return POM_OK;

}

int mgmtcmd_target_parameter_reset(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc != 3)
		return MGMT_USAGE;

	main_config_rules_lock(0);

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	target_lock(0);
	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	main_config_rules_unlock();

	if (!t) {
		target_unlock();
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}

	target_lock_instance(t, 1);
	target_unlock();

	if (t->started) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "Target must be stopped to change a parameter\r\n");
		return POM_OK;
	}
	

	struct target_param_reg *pr = t->mode->params;
	while (pr) {
		if (!strcmp(pr->name, argv[2]))
			break;
		pr = pr->next;
	}

	if (!pr) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "No parameter %s for target %s\r\n", argv[2], target_get_name(t->type));
		return POM_OK;
	}

	struct target_param *p = t->params;
	while (p) {
		if (p->type == pr)
			break;
		p = p->next;
	}

	if (!p) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "Could not find parameter %s for target %s\r\n", argv[2], target_get_name(t->type));
		return POM_OK;
	}

	if (ptype_parse_val(p->value, pr->defval) == POM_ERR) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "Unable to parse \"%s\" for parameter %s\r\n", pr->defval, argv[2]);
		return POM_OK;
	}

	main_config->target_serial++;
	rl->target_serial++;
	t->serial++;
	target_unlock_instance(t);

	return POM_OK;

}

struct mgmt_command_arg *mgmtcmd_target_parameter_set_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc == 3 || argc == 4) {

		res = mgmctcmd_target_id_completion(argc, argv, argc - 3);

	} else if (argc == 5) {
		int i = 0;
		int rule_id = -1;

		if (sscanf(argv[argc - 2], "%u", &rule_id) != 1)
			return NULL;

		int target_id = -1;
		if (sscanf(argv[argc - 1], "%u", &target_id) != 1)
			return NULL;

		main_config_rules_lock(0);

		struct rule_list *rl;
		for (rl = main_config->rules; rl && i < rule_id; rl = rl->next)
			i++;

		struct target *t;
		for (t = rl->target, i = 0; t && i < target_id; t = t->next)
			i++;
		
		if (!t || !t->mode) {
			main_config_rules_unlock();
			return NULL;
		}

		struct target_mode *m = t->mode;

		struct target_param_reg *p = m->params;

		while (p) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			char *name = p->name;
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;

			p = p->next;
		}

		main_config_rules_unlock();

	}
	return res;
}

int mgmtcmd_target_description_set(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 3)
		return MGMT_USAGE;

	main_config_rules_lock(0);

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	target_lock(0);
	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	main_config_rules_unlock();

	if (!t) {
		target_unlock();
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}

	target_lock_instance(t, 1);
	target_unlock();

	if (t->description)
		free(t->description);

	// first, let's reconstruct the whole description
	int target_descr_len = 0, i;
	for (i = 2; i < argc; i++) {
		target_descr_len += strlen(argv[i]) + 1;
	}
	char *target_descr = malloc(target_descr_len + 1);
	memset(target_descr, 0, target_descr_len + 1);
	for (i = 2; i < argc; i++) {
		strcat(target_descr, argv[i]);
		strcat(target_descr, " ");
	}
	target_descr[strlen(target_descr) - 1] = 0;
	t->description = target_descr;

	main_config->target_serial++;
	rl->target_serial++;
	t->serial++;
	target_unlock_instance(t);

	return POM_OK;

}

int mgmtcmd_target_description_unset(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	main_config_rules_lock(0);

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	target_lock(0);
	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	main_config_rules_unlock();

	if (!t) {
		target_unlock();
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}

	target_lock_instance(t, 1);
	target_unlock();

	if (t->description) {
		free(t->description);
		t->description = NULL;
		main_config->target_serial++;
		rl->target_serial++;
		t->serial++;
	} else {
		mgmtsrv_send(c, "Target %s %s has no description\r\n", argv[0], argv[1]);
	}

	target_unlock_instance(t);

	return POM_OK;

}
int mgmtcmd_target_mode_set(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 3)
		return MGMT_USAGE;

	main_config_rules_lock(0);

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		main_config_rules_unlock();
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	target_lock(0);
	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	main_config_rules_unlock();

	if (!t) {
		target_unlock();
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}

	target_lock_instance(t, 0);
	target_unlock();

	if (t->started) {
		target_unlock_instance(t);
		mgmtsrv_send(c, "Target must be stopped to change a parameter\r\n");
		return POM_OK;
	}

	if (target_set_mode(t, argv[2]) == POM_ERR) {
		mgmtsrv_send(c, "No mode \"%s\" for target %s\r\n", argv[3], target_get_name(t->type));
	} else {
		main_config->target_serial++;
		rl->target_serial++;
		t->serial++;
	}

	target_unlock_instance(t);

	return POM_OK;

}

struct mgmt_command_arg *mgmtcmd_target_mode_set_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc == 3 || argc == 4) {

		res = mgmctcmd_target_id_completion(argc, argv, argc - 3);

	} else if (argc == 5) {
		int i = 0;
		int rule_id = -1;

		if (sscanf(argv[argc - 2], "%u", &rule_id) != 1)
			return NULL;

		int target_id = -1;
		if (sscanf(argv[argc - 1], "%u", &target_id) != 1)
			return NULL;

		main_config_rules_lock(0);
		struct rule_list *rl;
		for (rl = main_config->rules; rl && i < rule_id; rl = rl->next)
			i++;

		struct target *t;
		for (t = rl->target, i = 0; t && i < target_id; t = t->next)
			i++;
		
		if (!t || !targets[t->type] || !targets[t->type]->modes) {
			main_config_rules_unlock();
			return NULL;
		}


		struct target_mode *m = targets[t->type]->modes;

		while (m) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			char *name = m->name;
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;

			m = m->next;
		}

		main_config_rules_unlock();

	}
	return res;
}

int mgmtcmd_target_help(struct mgmt_connection *c, int argc, char *argv[]) {


	int single = 0, id = 0, displayed = 0;
	if (argc >= 1) {
		single = 1;
		target_lock(1);
		id = target_register(argv[0]);
		if (id == POM_ERR) {
			target_unlock();
			mgmtsrv_send(c, "Non existing target %s\r\n", argv[0]);
			return POM_OK;
		}
		target_unlock();
	}

	target_lock(0);
	for (; id < MAX_TARGET; id++) {
		char *name = target_get_name(id);
		if (!name)
			continue;

		displayed++;

		mgmtsrv_send(c, "Target %s :\r\n", name);

		struct target_mode *tm = targets[id]->modes;

		while (tm) {

			mgmtsrv_send(c, "  mode %s : %s\r\n", tm->name, tm->descr);

			struct target_param_reg* tp = tm->params;
			if (!tp) {
				mgmtsrv_send(c, "    no parameter for this mode\r\n");
			} else {
				while (tp) {
					mgmtsrv_send(c, "    %s : %s (default : '%s')\r\n", tp->name, tp->descr, tp->defval);
					
					tp = tp->next;
				}
			}
			tm = tm->next;
		}

		mgmtsrv_send(c, "\r\n");

		if (single)
			break;
	}

	target_unlock();

	if (!displayed)
		mgmtsrv_send(c, "No target loaded\r\n");

	return POM_OK;
}

int mgmtcmd_target_load(struct mgmt_connection *c, int argc, char*argv[]) {

	if (argc != 1)
		return MGMT_USAGE;
	target_lock(1);	
	if (target_get_type(argv[0]) != POM_ERR) {
		target_unlock();
		mgmtsrv_send(c, "Target %s is already registered\r\n", argv[0]);
		return POM_OK;
	}

	int id = target_register(argv[0]);
	target_unlock();
	if (id == POM_ERR)
		mgmtsrv_send(c, "Error while loading target %s\r\n", argv[0]);
	else
		mgmtsrv_send(c, "Target %s regitered with id %u\r\n", argv[0], id);

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_target_avail_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("target");
	return res;
}

int mgmtcmd_target_unload(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;
	
	target_lock(1);
	int id = target_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Target %s not loaded\r\n", argv[0]);
	} else if (targets[id]->refcount) {
		mgmtsrv_send(c, "Target %s is still in use. Cannot unload it\r\n", argv[0]);
	} else if (target_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Target %s unloaded successfully\r\n", argv[0]);
	} else {
		mgmtsrv_send(c, "Error while unloading target %s\r\n", argv[0]);
	}

	target_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_target_unload_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc != 2)
		return NULL;

	int i;
	for (i = 0; i < MAX_TARGET; i++) {
		if (targets[i]) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			char *name = targets[i]->name;
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;
		}

	}

	return res;
}
