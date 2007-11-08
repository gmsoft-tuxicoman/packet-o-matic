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
#include "ptype_bool.h"
#include "ptype_uint8.h"
#include "ptype_uint16.h"

int match_undefined_id;

struct target_functions *tf;
struct target_mode *mode_normal, *mode_connection;

int target_register_display(struct target_reg *r, struct target_functions *tg_funcs) {

	r->init = target_init_display;
	r->process = target_process_display;
	r->close = target_close_display;
	r->cleanup = target_cleanup_display;

	tf = tg_funcs;

	match_undefined_id = (*tf->match_register) ("undefined");

	mode_normal = (*tf->register_mode) (r->type, "normal", "Display the headers fields and dump");
	mode_connection = (*tf->register_mode) (r->type, "connection", "Display each new connection and a summary");

	if (!mode_normal || !mode_connection)
		return POM_ERR;

	(*tf->register_param) (mode_normal, "skip", "0", "Number of headers to skip");
	(*tf->register_param) (mode_normal, "debug_level", "3", "Default debug level that target_display will use");
	(*tf->register_param) (mode_normal, "print_hex", "no", "Show dump of the packet in hex");
	(*tf->register_param) (mode_normal, "print_ascii", "no", "Show dump of the packet in ascii");
	(*tf->register_param) (mode_normal, "conntrack", "no", "Save conntrack info to see all the connection packets");

	(*tf->register_param) (mode_connection, "skip", "0", "Number of headers to skip");

	return POM_OK;

}

int target_init_display(struct target *t) {

	struct target_priv_display *priv = malloc(sizeof(struct target_priv_display));
	bzero(priv, sizeof(struct target_priv_display));

	t->target_priv = priv;

	priv->skip = (*tf->ptype_alloc) ("uint16", "headers");
	priv->debug_level = (*tf->ptype_alloc) ("uint8", NULL);
	priv->print_hex = (*tf->ptype_alloc) ("bool", NULL);
	priv->print_ascii = (*tf->ptype_alloc) ("bool", NULL);
	priv->conntrack = (*tf->ptype_alloc) ("bool", NULL);

	if (!priv->skip) {
		free(priv);
		return POM_ERR;
	}

	(*tf->register_param_value) (t, mode_normal, "skip", priv->skip);
	(*tf->register_param_value) (t, mode_normal, "debug_level", priv->debug_level);
	(*tf->register_param_value) (t, mode_normal, "print_hex", priv->print_hex);
	(*tf->register_param_value) (t, mode_normal, "print_ascii", priv->print_ascii);
	(*tf->register_param_value) (t, mode_normal, "conntrack", priv->conntrack);

	(*tf->register_param_value) (t, mode_connection, "skip", priv->skip);

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

	if (PTYPE_BOOL_GETVAL(p->conntrack) || t->mode == mode_connection) {
		if (!f->ce)
			(*tf->conntrack_create_entry) (f);

		struct target_conntrack_priv_display *cp;
		cp = (*tf->conntrack_get_priv) (t, f->ce);

		if (!cp) {
			cp = malloc(sizeof(struct target_conntrack_priv_display));
			bzero(cp, sizeof(struct target_conntrack_priv_display));
			(*tf->conntrack_add_priv) (cp, t, f->ce, target_close_connection_display);

			cp->ce = f->ce;
			cp->next = p->ct_privs;
			if (p->ct_privs)
				p->ct_privs->prev = cp;
			p->ct_privs = cp;
		} else if (t->mode == mode_connection)
			return POM_OK;
	}

	unsigned char debug_level = PTYPE_UINT8_GETVAL(p->debug_level);

	struct layer *start_layer = l;
	char line[2048];
	bzero(line, sizeof(line));
	int freesize = sizeof(line) - 1;

	if (t->mode == mode_connection) {
		char *msg = "New connection : ";
		strcat(line, msg);
		freesize -= strlen(msg);
	}

	int first_layer = 1, first_field, len;

	char buff[1024];

	while (l && l->type != match_undefined_id) {
	
		if (!first_layer) {
			char *coma = ", ";
			strncat(line, coma, freesize);
			freesize -= strlen(coma);
		} else
			first_layer = 0;
	
		first_field = 1;
	
		char *match_name = (*tf->match_get_name) (l->type);
		strncat(line, match_name, freesize);
		freesize -= strlen(match_name);


		if (l->fields) {
		

			int i;
			for (i = 0; i < MAX_LAYER_FIELDS && l->fields[i]; i++) {
				len = (*tf->ptype_print_val) (l->fields[i], buff, sizeof(buff) - 1);

				if (len) {
					if (!first_field) {
						char *semicolon = "; ";
						strncat(line, semicolon, freesize);
						freesize -= strlen(semicolon);
					} else {
						char *fstart = " [";
						strncat(line, fstart, freesize);
						freesize -= strlen(fstart);
						first_field = 0;
					}
					
					struct match_field_reg *field = (*tf->match_get_field) (l->type, i);
						
					strncat(line, field->name, freesize);
					freesize -= strlen(field->name);

					char *colon = ": ";
					strncat(line, colon, freesize);
					freesize -= strlen(colon);

					strncat(line, buff, freesize);
					freesize -= len;
				}

			}

			if (!first_field) {
				char *fend = "]";
				strncat(line, fend, freesize);
				freesize -= strlen(fend);
			}
		}

		l = l->next;
	}

	if (t->mode == mode_normal) { // We don't care about the len in connection mode
		len = snprintf(buff, freesize, " [len: %u]", f->len);
		strncat(line, buff, freesize);
		freesize -= len;
	}

	l = start_layer;

	char *format_str = " %s\r\n";
	char format[strlen(format_str) + 1];
	strcpy(format, format_str);
	format[0] = debug_level;
	(*tf->pom_log) (format, line);


	int start = 0;
	len = f->len;
	if (l->prev) {
		start = l->prev->payload_start;
		len = l->payload_size + l->payload_start - l->prev->payload_start;
	}
	
	if (len <= 0)
		return POM_OK;

	if (t->mode == mode_normal) {

		if (PTYPE_BOOL_GETVAL(p->print_hex))
			return target_display_print_hex(f->buff, start, len, p);
		else if (PTYPE_BOOL_GETVAL(p->print_ascii))
			return target_display_print_ascii(f->buff, start, len, p);
	}

	return POM_OK;

}

int target_display_print_hex(void *frame, unsigned int start, unsigned int len, struct target_priv_display *p) {


	unsigned char *f = frame + start;

	int pos = 0, linepos = 1;
	char line[256];
	bzero(line, sizeof(line));

	while (pos < len) {
		bzero(line, sizeof(line));
		linepos = 0;

		linepos += sprintf(line + linepos, "\t0x%04x:  ", pos);

		int i, max;
		max = pos + 16;
		if (max > len)
			max = len;

		for (i = pos; i < max; i++) {
			linepos += sprintf(line + linepos, "%02x", f[i]);
			if (i & 0x1) {
				line[linepos] = ' ';
				linepos++;
			}
		}

		int diff = len - pos;
		if (diff < 16) {
			diff = 16 - diff;
			int space = (diff * 2) + (diff >> 1) + (diff & 0x1);
			for (i = 0; i < space; i++) {
				line[linepos] = ' ';
				linepos++;
			}
		}
		if (PTYPE_BOOL_GETVAL(p->print_ascii)) {
			line[linepos] = ' ';
			linepos++;

			for (i = pos; i < max; i++) {
				if ((f[i] >= ' ' && f[i] <= '~')) {
					line[linepos] = f[i];
				} else {
					line[linepos] = '.';
				}
				linepos++;
			}
		}

		pos = max;

		char *format_str = " %s\r\n";
		char format[strlen(format_str) + 1];
		strcpy(format, format_str);
		format[0] = PTYPE_UINT8_GETVAL(p->debug_level);
		(*tf->pom_log) (format, line);
	}
	
	return POM_OK;

}


int target_display_print_ascii(void *frame, unsigned int start, unsigned int len, struct target_priv_display *p) {

	unsigned char *f = frame + start;
	int i;
	char line[2048];
	bzero(line, sizeof(line));
	int linepos = 0;

	for (i = 0; i < len; i++) {
		if ((f[i] >= ' ' && f[i] <= '~') || f[i] == '\n')
			line[linepos] = f[i];
		else
			line[linepos] = '.';
		linepos++;
		if (linepos >= sizeof(line) - 2)
			break;

	}
	char *format_str = " %s\r\n";
	char format[strlen(format_str) + 1];
	strcpy(format, format_str);
	format[0] = PTYPE_UINT8_GETVAL(p->debug_level);
	(*tf->pom_log) (format, line);
	return POM_OK;

}

int target_close_display(struct target *t) {

	struct target_priv_display *priv = t->target_priv;

	while (priv->ct_privs) {
		(*tf->conntrack_remove_priv) (priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_display(t, priv->ct_privs->ce, priv->ct_privs);

	}
	

	return POM_OK;
}

int target_cleanup_display(struct target *t) {

	struct target_priv_display *priv = t->target_priv;

	if (priv) {
		(*tf->ptype_cleanup) (priv->skip);
		(*tf->ptype_cleanup) (priv->debug_level);
		(*tf->ptype_cleanup) (priv->print_hex);
		(*tf->ptype_cleanup) (priv->print_ascii);
		(*tf->ptype_cleanup) (priv->conntrack);
		free(t->target_priv);
	}

	return POM_OK;
}

int target_close_connection_display(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	struct target_priv_display *priv = t->target_priv;
	struct target_conntrack_priv_display *cp = conntrack_priv;

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;
	
	free(cp);

	return POM_OK;

}
