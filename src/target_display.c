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
#include "ptype_uint16.h"

int match_undefined_id;

struct target_functions *target_funcs;
struct target_mode *mode_normal, *mode_ascii, *mode_hex;

int target_register_display(struct target_reg *r, struct target_functions *tg_funcs) {

	r->init = target_init_display;
	r->process = target_process_display;
	r->cleanup = target_cleanup_display;

	target_funcs = tg_funcs;

	match_undefined_id = (*target_funcs->match_register) ("undefined");

	mode_normal = (*tg_funcs->register_mode) (r->type, "normal", "Display the headers only");
	mode_ascii = (*tg_funcs->register_mode) (r->type, "ascii", "Display the headers and a dump of the printable characters");
	mode_hex = (*tg_funcs->register_mode) (r->type, "hex", "Display the headers and an hex dump of the packet content");

	if (!mode_normal || !mode_ascii || !mode_hex)
		return POM_ERR;

	(*tg_funcs->register_param) (mode_normal, "skip", "0", "Number of headers to skip");
	(*tg_funcs->register_param) (mode_ascii, "skip", "0", "Number of headers to skip");
	(*tg_funcs->register_param) (mode_hex, "skip", "0", "Number of headers to skip");

	return POM_OK;

}

int target_init_display(struct target *t) {

	struct target_priv_display *priv = malloc(sizeof(struct target_priv_display));
	bzero(priv, sizeof(struct target_priv_display));

	t->target_priv = priv;

	priv->skip = (*target_funcs->ptype_alloc) ("uint16", "headers");

	if (!priv->skip) {
		free(priv);
		return POM_ERR;
	}

	(*target_funcs->register_param_value) (t, mode_normal, "skip", priv->skip);
	(*target_funcs->register_param_value) (t, mode_ascii, "skip", priv->skip);
	(*target_funcs->register_param_value) (t, mode_hex, "skip", priv->skip);

	return POM_OK;
}


int target_process_display(struct target *t, struct frame *f) {

	struct target_priv_display *p = t->target_priv;

	struct layer *l = f->l;
	int i;
	for (i = 0; i < PTYPE_UINT16_GETVAL(p->skip) && l; i++)
		l = l->next;

	if (!l) {
		// Skip is higher than number of layers, skip this packet
		return POM_OK;
	}

	struct layer *start_layer = l;
	const int buffsize = 2048;
	char buff[buffsize];
	int first_layer = 0, first_info = 0;

	while (l && l->type != match_undefined_id) {
	
		if (first_layer)
			printf(", ");
		
		first_layer = 1;

		printf("%s", (*target_funcs->match_get_name) (l->type));

		if (l->infos && l->infos->name) {
		

			first_info = 1;
			
			struct layer_info *inf = l->infos;
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

		l = l->next;
	}

	printf(" [len: %u]\n", f->len);

	l = start_layer;

	int start = 0;
	unsigned int len = 0;
	if (l->prev) {
		start = l->prev->payload_start;
		len = l->payload_size + l->payload_start - l->prev->payload_start;
	}
	

	if (t->mode == mode_hex)
		return target_display_print_hex(f->buff, start, len);

	if (t->mode == mode_ascii)
		return target_display_print_ascii(f->buff, start, len);

	return POM_OK;

}

int target_display_print_hex(void *frame, unsigned int start, unsigned int len) {


	unsigned char *f = frame + start;

	int pos = 0;

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

		int diff = len - pos;
		if (diff < 16) {
			diff = 16 - diff;
			int space = (diff * 2) + (diff >> 1) + (diff & 0x1);
			for (i = 0; i < space; i++)
				printf(" ");
		}
		printf(" ");

		for (i = pos; i < max; i++) {
			if ((f[i] >= ' ' && f[i] <= '~'))
				printf("%c", f[i]);
			else
				printf(".");
		}
		pos = i;
		printf("\n");

	}
	
	return POM_OK;

}


int target_display_print_ascii(void *frame, unsigned int start, unsigned int len) {

	unsigned char *f = frame + start;
	int i;
	for (i = 0; i < len; i++) {
		if ((f[i] >= ' ' && f[i] <= '~') || f[i] == '\n')
			printf("%c", f[i]);
		else
			printf(".");

	}
	printf("\n");
	return POM_OK;

}


int target_cleanup_display(struct target *t) {

	struct target_priv_display *priv = t->target_priv;

	if (priv) {
		(*target_funcs->ptype_cleanup) (priv->skip);
		free(t->target_priv);
	}

	return POM_OK;
}
