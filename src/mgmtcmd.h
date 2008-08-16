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

#ifndef __MGMTCMD_H__
#define __MGMTCMD_H__

#include "ptype.h"

int mgmtcmd_register_all();
int mgmtcmd_exit(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_help(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_print_help(struct mgmt_connection *c, struct mgmt_command *start, struct mgmt_command *end);
int mgmtcmd_show_license(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_password(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_unset_password(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_debug_level(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_set_debug_level_completion(int argc, char *argv[]);
int mgmtcmd_show_debug_level(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_console_debug(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_write_config(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_halt(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_show_core_parameters(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_core_parameter(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_set_core_parameter_completion(int argc, char *argv[]);
int mgmtcmd_load_match(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_load_match_completion(int argc, char *argv[]);
int mgmtcmd_unload_match(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_unload_match_completion(int argc, char *argv[]);
int mgmtcmd_load_ptype(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_load_ptype_completion(int argc, char *argv[]);
int mgmtcmd_unload_ptype(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_unload_ptype_completion(int argc, char *argv[]);
int mgmtcmd_show_version(struct mgmt_connection *c, int argc, char*argv[]);

struct mgmt_command_arg* mgmtcmd_list_modules(char *type);
struct mgmt_command_arg *mgmtcmd_completion_int_range(int start, int count);

#endif
