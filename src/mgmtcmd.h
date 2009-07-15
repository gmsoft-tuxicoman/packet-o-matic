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

#ifndef __MGMTCMD_H__
#define __MGMTCMD_H__

#include "ptype.h"

int mgmtcmd_register_all();
int mgmtcmd_exit(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_help(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_print_help(struct mgmt_connection *c, struct mgmt_command *commands);
int mgmtcmd_license_show(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_password_cli_set(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_password_cli_unset(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_debug_cli_set(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_debug_set_completion(int argc, char *argv[]);
int mgmtcmd_debug_cli_show(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_debug_console_set(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_debug_console_show(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_debug_show(struct mgmt_connection *c, int level);
int mgmtcmd_config_write(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_halt(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_core_parameter_show(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_core_parameter_set(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_core_parameter_set_completion(int argc, char *argv[]);
int mgmtcmd_match_load(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_match_help(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_match_avail_completion(int argc, char *argv[]);
int mgmtcmd_match_unload(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_match_unload_completion(int argc, char *argv[]);
int mgmtcmd_ptype_load(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_ptype_load_completion(int argc, char *argv[]);
int mgmtcmd_ptype_unload(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_ptype_unload_completion(int argc, char *argv[]);
int mgmtcmd_version_show(struct mgmt_connection *c, int argc, char*argv[]);

struct mgmt_command_arg* mgmtcmd_list_modules(char *type);
struct mgmt_command_arg *mgmtcmd_completion_int_range(int start, int count);

#endif
