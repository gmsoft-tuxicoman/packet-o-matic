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

#ifndef __MGMTCMD_TARGET_H__
#define __MGMTCMD_TARGET_H__

#include "common.h"
#include "main.h"
#include "mgmtsrv.h"
#include "mgmtcmd.h"

int mgmtcmd_target_register_all();
struct mgmt_command_arg *mgmctcmd_target_id_completion(int argc, char *argv[], int pos);
struct mgmt_command_arg *mgmtcmd_target_completion_id2(int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_target_completion_id3(int argc, char *argv[]);
int mgmtcmd_show_targets(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_start_target(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_stop_target(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_add_target(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_target_name_completion(int argc, char *argv[]);
int mgmtcmd_remove_target(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_target_parameter(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_set_target_parameter_completion(int argc, char *argv[]);
int mgmtcmd_set_target_descr(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_unset_target_descr(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_target_mode(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_set_target_mode_completion(int argc, char *argv[]);
int mgmtcmd_load_target(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_load_target_completion(int argc, char *argv[]);
int mgmtcmd_unload_target(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_unload_target_completion(int argc, char *argv[]);

#endif
