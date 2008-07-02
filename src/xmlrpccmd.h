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


#ifndef __XMLRPCCMD_H__
#define __XMLRPCCMD_H__

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>

int xmlrpccmd_register_all();


xmlrpc_value *xmlrpccmd_get_core_parmeters(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_set_core_parmeter(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_main_get_serial(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_main_halt(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_main_set_password(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_get_logs(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);

xmlrpc_value *xmlrpccmd_list_avail_modules(xmlrpc_env * const envP, char *type);

#endif

