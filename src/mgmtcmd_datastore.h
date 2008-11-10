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

#ifndef __MGMTCMD_DATASTORE_H__
#define __MGMTCMD_DATASTORE_H__

#include "common.h"
#include "main.h"
#include "mgmtsrv.h"
#include "mgmtcmd.h"

int mgmtcmd_datastore_register_all();
struct mgmt_command_arg *mgmctcmd_datastore_name_completion(int argc, char *argv[], int pos);
struct mgmt_command_arg *mgmtcmd_datastore_completion_name2(int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_datastore_completion_name3(int argc, char *argv[]);
int mgmtcmd_show_datastores(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_start_datastore(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_stop_datastore(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_add_datastore(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_datastore_type_completion(int argc, char *argv[]);
int mgmtcmd_remove_datastore(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_datastore_parameter(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_set_datastore_parameter_completion(int argc, char *argv[]);
int mgmtcmd_set_datastore_descr(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_unset_datastore_descr(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_datastore_mode(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg *mgmtcmd_set_datastore_mode_completion(int argc, char *argv[]);
int mgmtcmd_load_datastore(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_load_datastore_completion(int argc, char *argv[]);
int mgmtcmd_unload_datastore(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_unload_datastore_completion(int argc, char *argv[]);

struct datastore *mgmtcmd_get_datastore(char *datastore);
#endif
