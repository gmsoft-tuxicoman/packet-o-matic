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


#include <errno.h>

#include "target_display.h"

#define PARAMS_NUM 2
char *target_display_params[PARAMS_NUM][3] = {
	{ "skip", "0", "number of layers to skip" },
	{ "mode", "normal", "mode of display : normal (display only header summary), ascii (display printable chars), hex (display hex dump)" },
};


int match_undefined_id;

struct target_functions *target_funcs;

int target_register_display(struct target_reg *r, struct target_functions *tg_funcs) {

	copy_params(r->params_name, target_display_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_display_params, 2, PARAMS_NUM);

	r->init = target_init_display;
	r->open = target_open_display;
	r->process = target_process_display;
	r->cleanup = target_cleanup_display;

	target_funcs = tg_funcs;

	match_undefined_id = (*target_funcs->match_register) ("undefined");

	return 1;

}

int target_init_display(struct target *t) {

	copy_params(t->params_value, target_display_params, 1, PARAMS_NUM);

	struct target_priv_display *priv = malloc(sizeof(struct target_priv_display));
	bzero(priv, sizeof(struct target_priv_display));

	t->target_priv = priv;

	return 1;
}

int target_open_display(struct target *t) {

	struct target_priv_display *priv = t->target_priv;

	sscanf(t->params_value[0], "%u", &priv->skip);

	if (!strcmp(t->params_value[1], "hex")) {
		priv->mode = td_mode_hex;
	} else if (!strcmp(t->params_value[1], "ascii")) {
		priv->mode = td_mode_ascii;
	} else {
		priv->mode = td_mode_normal;
	}
	return 1;
}

int target_process_display(struct target *t, struct layer *l, void *frame, unsigned int len, struct conntrack_entry *ce) {

	struct target_priv_display *p = t->target_priv;

	struct layer *tmpl = l;
	int i;
	for (i = 0; i < p->skip && tmpl; i++)
		tmpl = tmpl->next;

	if (!tmpl) {
		// Skip is higher than number of layers, skip this packet
		return 1;
	}

	const int buffsize = 2048;
	char buff[buffsize];
	int first_layer = 0, first_info = 0;

	while (tmpl && tmpl->type != match_undefined_id) {
	
		if (first_layer)
			printf(", ");
		
		first_layer = 1;

		printf("%s", (*target_funcs->match_get_name) (tmpl->type));

		if (tmpl->infos && tmpl->infos->name) {
		

			first_info = 1;
			
			struct layer_info *inf = tmpl->infos;
			while (inf) {
				if ((*target_funcs->layer_info_snprintf) (buff, buffsize, inf)) {

					if (!first_info)
						printf("; ");
					else
						printf(" [");

					printf("%s: %s", inf->name, buff);
					first_info = 0;
				}

				inf = inf->next;

			}

			if (!first_info)
				printf("]");
		}

		tmpl = tmpl->next;
	}

	printf("\n");

	int start;
	if (l->prev)
		start = l->prev->payload_start;
	else
		start = 0;
	

	switch (p->mode) {
		case td_mode_hex:
			target_display_print_hex(frame, start, len);
			break;

		case td_mode_ascii:
			target_display_print_ascii(frame, start, len);
			break;
	}


	return 1;

}

int target_display_print_hex(void *frame, unsigned int start, unsigned int len) {

	int pos = start;

	unsigned char *f = frame;

	while (pos < len) {

		printf("\t0x%04x:  ", pos);

		int i, max;
		max = pos + 16;
		if (max > len)
			max = len;

		for (i = pos; i < max; i++) {
			printf("%02x", f[i]);
			if (i & 0x1)
				printf(" ");
		}

		for (i = pos; i < max; i++) {
			if ((f[i] >= ' ' && f[i] <= '~'))
				printf("%c", f[i]);
			else
				printf(".");
		}
		pos = i;
		printf("\n");

	}
	printf("\n");
	
	return 1;

}


int target_display_print_ascii(void *frame, unsigned int start, unsigned int len) {

	unsigned char *f = frame;
	int i;
	for (i = start; i < len; i++) {
		if ((f[i] >= ' ' && f[i] <= '~') || f[i] == '\n' || f[i] =='\r')
			printf("%c", f[i]);
		else
			printf(".");

	}
	printf("\n");
	return 1;

}


int target_cleanup_display(struct target *t) {

	clean_params(t->params_value, PARAMS_NUM);

	if (t->target_priv)
		free(t->target_priv);

	return 1;
}
