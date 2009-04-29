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
int mgmtcmd_target_show(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_target_start(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_target_stop(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_target_add(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_target_name_completion(int argc, char *argv[]);
int mgmtcmd_target_remove(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_target_parameter_set(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_target_parameter_set_completion(int argc, char *argv[]);
int mgmtcmd_target_description_set(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_target_description_unset(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_target_mode_set(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_target_mode_set_completion(int argc, char *argv[]);
int mgmtcmd_target_load(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_target_load_completion(int argc, char *argv[]);
int mgmtcmd_target_unload(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_target_unload_completion(int argc, char *argv[]);

#endif
