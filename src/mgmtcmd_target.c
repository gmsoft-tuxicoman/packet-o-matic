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



#include "mgmtcmd_target.h"
#include "mgmtcmd_rule.h"
#include "target.h"


#define MGMT_TARGET_COMMANDS_NUM 9

struct mgmt_command mgmt_target_commands[MGMT_TARGET_COMMANDS_NUM] = {

	{
		.words = { "show", "targets", NULL },
		.help = "Display informations about the targets in every rule",
		.callback_func = mgmtcmd_show_targets,
	},

	{
		.words = { "start", "target", NULL },
		.help = "Start a target",
		.callback_func = mgmtcmd_start_target,
		.usage = "start target <rule_id> <target_id>",
	},

	{
		.words = { "stop", "target", NULL },
		.help = "Stop a target",
		.callback_func = mgmtcmd_stop_target,
		.usage = "stop target <rule_id> <target_id>",
	},

	{
		.words = { "add", "target", NULL },
		.help = "Add a target to a rule",
		.callback_func = mgmtcmd_add_target,
		.usage = "add target <rule_id> <target>",
	},

	{
		.words = { "remove", "target", NULL },
		.help = "Remove a target from a rule",
		.callback_func = mgmtcmd_remove_target,
		.usage = "remove target <rule_id> <target_id>",
	},

	{
		.words = { "set", "target", "parameter", NULL },
		.help = "Change the value of a target parameter",
		.callback_func = mgmtcmd_set_target_parameter,
		.usage = "set target parameter <rule_id> <target_id> <parameter> <value>",
	},

	{
		.words = { "set", "target", "mode", NULL },
		.help = "Change the mode of a target",
		.callback_func = mgmtcmd_set_target_mode,
		.usage = "set target mode <rule_id> <target_id> <mode>",
	},

	{
		.words = { "load", "target", NULL },
		.help = "Load a target into the system",
		.usage = "load target <target>",
		.callback_func = mgmtcmd_load_target,
	},

	{
		.words = { "unload", "target", NULL },
		.help = "Unload a target from the system",
		.usage = "unload target <target>",
		.callback_func = mgmtcmd_unload_target,
	},
};

int mgmtcmd_target_register_all() {

	int i;

	for (i = 0; i < MGMT_TARGET_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_target_commands[i]);
	}

	return POM_OK;
}

int mgmtcmd_show_targets(struct mgmt_connection *c, int argc, char *argv[]) {


	struct rule_list *rl = main_config->rules;

	unsigned int rule_num = 0, target_num;

	while (rl) {
		char pkts[16], bytes[16];
		ptype_print_val(rl->pkt_cnt, pkts, sizeof(pkts));
		ptype_print_val(rl->byte_cnt, bytes, sizeof(bytes));
		mgmtsrv_send(c, "Rule %u : targets (%s %s, %s %s)", rule_num, pkts, rl->pkt_cnt->unit, bytes, rl->byte_cnt->unit);
		if (!rl->enabled)
			mgmtsrv_send(c, " (disabled)");
		mgmtsrv_send(c, " : \r\n");

		struct target *t = rl->target;

		target_num = 0;

		while (t) {
			mgmtsrv_send(c, "   %u) %s", target_num, target_get_name(t->type));
			if (t->mode) {
				ptype_print_val(t->pkt_cnt, pkts, sizeof(pkts));
				ptype_print_val(t->byte_cnt, bytes, sizeof(bytes));
				mgmtsrv_send(c, ", mode %s (%s %s, %s %s)", t->mode->name, pkts, t->pkt_cnt->unit, bytes, t->byte_cnt->unit);
				if (!t->started)
					mgmtsrv_send(c, " (stopped)");
				mgmtsrv_send(c, "\r\n");
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
			mgmtsrv_send(c, "\r\n");
			t = t->next;
			target_num++;
		}

		rl = rl->next;
		rule_num++;
	}

	return POM_OK;
}

int mgmtcmd_start_target(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	if (!t) {
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}


	if (t->started) {
		mgmtsrv_send(c, "Target already started\r\n");
		return POM_OK;
	}
	
	reader_process_lock();

	if (target_open(t) != POM_OK) {
		mgmtsrv_send(c, "Error while starting the target\r\n");
		reader_process_unlock();
		return POM_OK;
	}

	reader_process_unlock();

	return POM_OK;

}

int mgmtcmd_stop_target(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	if (!t) {
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}


	if (!t->started) {
		mgmtsrv_send(c, "Target already stopped\r\n");
		return POM_OK;
	}
	
	reader_process_lock();

	if (target_close(t) != POM_OK) {
		mgmtsrv_send(c, "Error while stopping the target\r\n");
		reader_process_unlock();
		return POM_OK;
	}

	reader_process_unlock();

	return POM_OK;

}

int mgmtcmd_add_target(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	int target_type = target_register(argv[1]);

	if (target_type == POM_ERR) {
		mgmtsrv_send(c, "Target %s not found\r\n", argv[1]);
		return POM_OK;
	}
	
	struct target *t = target_alloc(target_type);
	if (!t) {
		mgmtsrv_send(c, "Error while allocating the target !!!\r\n");
		return POM_ERR;
	}

	reader_process_lock();

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

	reader_process_unlock();

	mgmtsrv_send(c, "Added target with id %u to rule %s\r\n", target_id, argv[0]);

	return POM_OK;

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

int mgmtcmd_remove_target(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	if (!t) {
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}


	reader_process_lock();

	if (t->started)
		target_close(t);

	if (t->prev)
		t->prev->next = t->next;
	else
		rl->target = t-> next;
	
	if (t->next)
		t->next->prev = t->prev;

	target_cleanup_module(t);

	reader_process_unlock();

	mgmtsrv_send(c, "Target removed\r\n");

	return POM_OK;

}

int mgmtcmd_set_target_parameter(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 4)
		return MGMT_USAGE;

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	if (!t) {
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}


	if (t->started) {
		mgmtsrv_send(c, "Target must be stopped to change a parameter\r\n");
		return POM_OK;
	}
	

	struct ptype *value =  target_get_param_value(t, argv[2]);
	if (!value) {
		mgmtsrv_send(c, "No parameter %s for target %s\r\n", argv[2], target_get_name(t->type));
		return POM_OK;
	}

	reader_process_lock();

	if (ptype_parse_val(value, argv[3]) == POM_ERR) {
		mgmtsrv_send(c, "Unable to parse \"%s\" for parameter %s\r\n", argv[3], argv[2]);
		reader_process_unlock();
		return POM_OK;
	}

	reader_process_unlock();

	return POM_OK;

}

int mgmtcmd_set_target_mode(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 3)
		return MGMT_USAGE;

	struct rule_list *rl = mgmtcmd_get_rule(argv[0]);

	if (!rl) {
		mgmtsrv_send(c, "Rule not found\r\n");
		return POM_OK;
	}

	struct target *t = mgmtcmd_get_target(rl, argv[1]);

	if (!t) {
		mgmtsrv_send(c, "Target not found\r\n");
		return POM_OK;
	}


	if (t->started) {
		mgmtsrv_send(c, "Target must be stopped to change a parameter\r\n");
		return POM_OK;
	}
	
	reader_process_lock();

	if (target_set_mode(t, argv[2]) == POM_ERR) {
		mgmtsrv_send(c, "No mode \"%s\" for target %s\r\n", argv[3], target_get_name(t->type));
		reader_process_unlock();
		return POM_OK;
	}

	reader_process_unlock();

	return POM_OK;

}

int mgmtcmd_load_target(struct mgmt_connection *c, int argc, char*argv[]) {

	if (argc != 1)
		return MGMT_USAGE;
	
	if (target_get_type(argv[0]) != POM_ERR) {
		mgmtsrv_send(c, "Target %s is already registered\r\n", argv[0]);
		return POM_OK;
	}

	int id = target_register(argv[0]);
	if (id == POM_ERR)
		mgmtsrv_send(c, "Error while loading target %s\r\n", argv[0]);
	else
		mgmtsrv_send(c, "Target %s regitered with id %u\r\n", argv[0], id);

	return POM_OK;

}

int mgmtcmd_unload_target(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = target_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Target %s not loaded\r\n", argv[0]);
		return POM_OK;
	}

	if (targets[id]->refcount) {
		mgmtsrv_send(c, "Target %s is still in use. Cannot unload it\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock();
	if (target_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Target % unloaded successfully\r\n", argv[0]);
	} else {
		mgmtsrv_send(c, "Error while unloading target %\r\n", argv[0]);
	}
	reader_process_unlock();
	
	return POM_OK;

}
