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

#ifndef __CORE_PARAM_H__
#define __CORE_PARAM_H__

#include "ptype.h"

struct core_param {

	char *name; ///< Name of the parameter
	char *defval; ///< Default value
	char *descr; ///< Description
	struct ptype *value; ///< User modifiable value
	int (*callback) (char *new_value, char *msg, size_t size); ///< Returns POM_ERR if action needs to be stopped otherwise POM_OK
	struct core_param *next;
};

int core_register_param(char *name, char *defval, struct ptype *value, char *descr, int (*callback) (char *new_value, char *msg, size_t size));
struct ptype* core_get_param_value(char *param);
int core_set_param_value(char *param, char *value, char *msg, size_t size);
struct core_param* core_param_get_head();
uint32_t core_param_get_serial();
int core_param_unregister_all();

#endif
