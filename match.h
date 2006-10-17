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

#include "common.h"


struct match {
	unsigned int match_type; // Type of match
	int next_start; // Position of the header for the next match
	int next_layer; // Next layer found
	int next_size; // Length of the packet's content
	void *match_priv;
	struct match *next;
	struct match *prev;
	char **params_value;
	int (*match_register) (const char *);
};

struct match_reg {

	char *match_name;
	void *dl_handle;
	char **params_name;
	char **params_help;
	int (*init) (struct match *m);
	int (*reconfig) (struct match *m);
	int (*eval) (struct match*, void*, unsigned int, unsigned int);
	int (*cleanup) (struct match *m);

};

int match_register(const char *match_name);
int match_get_type(const char *match_name);
struct match *match_alloc(int match_type);
int match_set_param(struct match *m, char *name, char *value);
int match_eval(struct match* m, void* frame, unsigned int start, unsigned int len);
int match_cleanup(struct match *m);
int match_unregister_all();
void match_print_help();



#endif

