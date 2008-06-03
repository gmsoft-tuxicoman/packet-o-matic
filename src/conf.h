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



#ifndef __CONF_H__
#define __CONF_H__

#include "common.h"

struct conf {

	struct input* input;
	struct rule_list *rules;
	char filename[NAME_MAX + 1];
	pthread_rwlock_t rules_lock;
};

struct conf *config_alloc();

int config_parse(struct conf*, char *);

int config_cleanup(struct conf*);

int config_write(struct conf *c, char *filename);


#endif
