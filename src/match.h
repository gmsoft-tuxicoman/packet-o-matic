/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
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

/// save infos about a match instance
struct match {
	unsigned int type; ///< type of match
	void *match_priv; ///< internal memory of the match
	char **params_value; ///< values of the parameters
};

/// save infos about a registered match
struct match_reg {

	char *name; ///< name of the match
	unsigned int type; ///< type of the match
	void *dl_handle; ///< handle of the library
	char **params_name; ///< parameter names
	char **params_help; ///< parameter help string
	int (*init) (struct match *m); ///< called when creating a new match
	int (*reconfig) (struct match *m); ///< called when parameters were updated
	int (*identify) (struct layer*, void*, unsigned int, unsigned int); ///< callled to identify the next layer of a packet
	int (*eval) (struct match*, void*, unsigned int, unsigned int, struct layer*); ///< called to check if the packet match what we want
	int (*cleanup) (struct match *m); ///< called when cleaning up the memory of the match
	int (*unregister) (struct match_reg *r); ///< called when unregistering the match

};

/// provide usefull fonction pointers to the inputs
struct match_functions {
	int (*match_register) (const char *); ///< register a match
	struct layer_info* (*layer_info_register) (unsigned int match_type, char *name, unsigned int flags); ///< add an info to a layer
};

int match_init();
int match_register(const char *match_name);
int match_get_type(const char *match_name);
char *match_get_name(int match_type);
struct match *match_alloc(int match_type);
int match_set_param(struct match *m, char *name, char *value);
int match_identify(struct layer *l, void* frame, unsigned int start, unsigned int len);
int match_eval(struct match* m, void* frame, unsigned int start, unsigned int len, struct layer *l);
int match_cleanup_module(struct match *m);
int match_cleanup();
int match_unregister(unsigned int match_type);
int match_unregister_all();
void match_print_help();



#endif

