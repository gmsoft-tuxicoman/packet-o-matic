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


#ifndef __XMLRPCCMD_CONNTRACK_H__
#define __XMLRPCCMD_CONNTRACK_H__

#include <xmlrpc-c/base.h>
#include <xmlrpc-c/server.h>

int xmlrpccmd_conntrack_register_all();

xmlrpc_value *xmlrpccmd_list_loaded_conntrack(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_set_conntrack_parameter(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_load_conntrack(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_unload_conntrack(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_list_avail_conntrack(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);


#endif

