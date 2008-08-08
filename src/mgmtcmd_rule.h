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

#ifndef __MGMTCMD_RULE_H__
#define __MGMTCMD_RULE_H__

#include "common.h"
#include "main.h"
#include "mgmtsrv.h"
#include "mgmtcmd.h"

#include "rules.h"

struct mgmt_command_arg* mgmtcmd_rule_id_completion();
struct mgmt_command_arg* mgmtcmd_rule_id2_completion(int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_rule_id3_completion(int argc, char *argv[]);
int mgmtcmd_rule_register_all();
int mgmtcmd_show_rules(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmt_show_rules_completion(int argc, char *argv[]);
int mgmtcmd_set_rule(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_disable_rule(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_enable_rule(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_add_rule(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_remove_rule(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_rule_descr(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_unset_rule_descr(struct mgmt_connection *c, int argc, char *argv[]);

struct rule_list *mgmtcmd_get_rule(char *rule);
struct target *mgmtcmd_get_target(struct rule_list *rl, char *target);


#endif
