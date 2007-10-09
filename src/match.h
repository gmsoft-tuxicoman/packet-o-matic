/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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



#ifndef __MATCH_H__
#define __MATCH_H__

#undef MAX_MATCH
#define MAX_MATCH 16

#include "layer.h"

/// Contains info about the possible parameters for this match
struct match_param_reg {
	char *name; ///< name of the parameter
	struct ptype *value; ///< value against which we must compare
	char *descr; ///< description of the parameter
	struct match_param_reg *next;

};

/// save infos about a registered match
struct match_reg {

	char *name; ///< name of the match
	unsigned int type; ///< type of the match
	struct match_param_reg *params; ///< possible parameters for the match
	void *dl_handle; ///< handle of the library
	int (*identify) (struct frame *f, struct layer*, unsigned int, unsigned int); ///< callled to identify the next layer of a packet
	int (*unregister) (struct match_reg *r); ///< called when unregistering the match

};

/// save info about a parameter
struct match_param {
	struct match_param_reg* field; ///< Field against which we should compare
	struct ptype *value; ///< Value that we should compare with
	int op; ///< Operator on the value

};

/// provide usefull fonction pointers to the inputs
struct match_functions {
	void (*pom_log) (const char *format, ...);
	int (*match_register) (const char *); ///< register a match
	int (*register_param) (int match_type, char *name, struct ptype *value, char *descr); ///< register a parameter for this match
	struct ptype* (*ptype_alloc) (const char* type, char* unit);
	int (*ptype_cleanup) (struct ptype* p);
	struct layer_info* (*layer_info_register) (unsigned int match_type, char *name, unsigned int flags); ///< add an info to a layer
};

int match_init();
int match_register(const char *match_name);
int match_register_param(int match_type, char *name, struct ptype *value, char *descr);
struct match_param *match_alloc_param(int match_type, char *param_type);
int match_cleanup_param(struct match_param *p);
int match_get_type(const char *match_name);
char *match_get_name(int match_type);
int match_identify(struct frame *f, struct layer *l, unsigned int start, unsigned int len);
int match_eval(struct match_param *mp);
int match_cleanup();
int match_unregister(unsigned int match_type);
int match_unregister_all();
void match_print_help();



#endif

