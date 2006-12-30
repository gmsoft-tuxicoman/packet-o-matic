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


struct match {
	unsigned int match_type; // Type of match
	void *match_priv;
	char **params_value;
	int (*match_register) (const char *);
};

struct layer {
	struct layer *next;
	struct layer *prev;
	int type;
	unsigned int payload_start;
	unsigned int payload_size;

};

struct match_reg {

	char *match_name;
	void *dl_handle;
	char **params_name;
	char **params_help;
	int (*init) (struct match *m);
	int (*reconfig) (struct match *m);
	int (*identify) (struct layer*, void*, unsigned int, unsigned int);
	int (*eval) (struct match*, void*, unsigned int, unsigned int, struct layer*);
	int (*cleanup) (struct match *m);

};

int match_init();
int match_register(const char *match_name);
int match_get_type(const char *match_name);
struct match *match_alloc(int match_type);
int match_set_param(struct match *m, char *name, char *value);
int match_identify(struct layer *l, void* frame, unsigned int start, unsigned int len);
int match_eval(struct match* m, void* frame, unsigned int start, unsigned int len, struct layer *l);
int match_cleanup(struct match *m);
int match_unregister_all();
void match_print_help();



#endif

