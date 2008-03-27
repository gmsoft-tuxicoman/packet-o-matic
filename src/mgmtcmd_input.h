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

#ifndef __MGMTCMD_INPUT_H__
#define __MGMTCMD_INPUT_H__

#include "common.h"
#include "main.h"
#include "mgmtsrv.h"
#include "mgmtcmd.h"

int mgmtcmd_input_register_all();
int mgmtcmd_show_input(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_start_input(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_stop_input(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_input_type(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_input_mode(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_set_input_parameter(struct mgmt_connection *c, int argc, char *argv[]);
int mgmtcmd_unload_input(struct mgmt_connection *c, int argc, char *argv[]);

#endif
