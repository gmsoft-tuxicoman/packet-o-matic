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


#include <errno.h>

#include "target_display.h"

int match_undefined_id;

struct target_functions *target_funcs;

int target_register_display(struct target_reg *r, struct target_functions *tg_funcs) {

	r->process = target_process_display;
	r->init = target_init_display;

	target_funcs = tg_funcs;

	return 1;

}

int target_init_display(struct target *t) {

	match_undefined_id = (*target_funcs->match_register) ("undefined");

	return 1;

}

int target_process_display(struct target *t, struct layer *l, void *frame, unsigned int len, struct conntrack_entry *ce) {


	struct layer *tmpl = l;

	const int buffsize = 2048;
	char buff[buffsize];

	while (tmpl && tmpl->type != match_undefined_id) {
		printf("%s", (*target_funcs->match_get_name) (tmpl->type));

		if (tmpl->infos && tmpl->infos->name) {
		
			printf(" [");
			
			struct layer_info *inf = tmpl->infos;
			while (inf) {
				if (!(*target_funcs->layer_info_snprintf) (buff, buffsize, inf))
					break;

				printf("%s: %s", inf->name, buff);

				if (inf->next)
					printf(", ");

				inf = inf->next;

			}

			printf("]");
		}
		printf("; ");

		tmpl = tmpl->next;
	}

	printf("\n");

	return 1;

}
