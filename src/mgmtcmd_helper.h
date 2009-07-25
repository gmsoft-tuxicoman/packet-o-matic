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

#ifndef __MGMTCMD_HELPER_H__
#define __MGMTCMD_HELPER_H__

#include "common.h"
#include "main.h"
#include "mgmtsrv.h"
#include "mgmtcmd.h"
#include "helper.h"

int mgmtcmd_helper_register_all();
int mgmtcmd_helper_show(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_helper_load(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_helper_load_completion(int argc, char *argv[]);
int mgmtcmd_helper_parameter_set(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_helper_parameter_reset(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_helper_parameter_set_completion(int argc, char *argv[]);
int mgmtcmd_helper_help(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_helper_unload(struct mgmt_connection *c, int argc, char *argv[]);
struct mgmt_command_arg* mgmtcmd_helper_loaded_completion(int argc, char *argv[]);

#endif
