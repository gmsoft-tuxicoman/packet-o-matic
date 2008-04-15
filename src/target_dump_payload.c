/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "target_dump_payload.h"

#include "ptype_bool.h"
#include "ptype_string.h"


unsigned int match_undefined_id;
struct target_mode *mode_default;

int target_register_dump_payload(struct target_reg *r) {

	r->init = target_init_dump_payload;
	r->process = target_process_dump_payload;
	r->close = target_close_dump_payload;
	r->cleanup = target_cleanup_dump_payload;

	match_undefined_id = match_register("undefined");

	mode_default = target_register_mode(r->type, "default", "Dump each connection into separate files");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "prefix", "dump", "Prefix of dumped filenames including path");
	target_register_param(mode_default, "markdir", "no", "Mark the direction of each packets in dumped files");

	return POM_OK;

}

int target_init_dump_payload(struct target *t) {

	struct target_priv_dump_payload *priv = malloc(sizeof(struct target_priv_dump_payload));
	memset(priv, 0, sizeof(struct target_priv_dump_payload));

	t->target_priv = priv;

	priv->prefix = ptype_alloc("string", NULL);
	priv->markdir = ptype_alloc("bool", NULL);

	if (!priv->prefix || !priv->markdir) {
		target_cleanup_dump_payload(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "prefix", priv->prefix);
	target_register_param_value(t, mode_default, "markdir", priv->markdir);

	return POM_OK;
}

int target_close_dump_payload(struct target *t) {

	struct target_priv_dump_payload *priv = t->target_priv;

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_dump_payload(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

int target_cleanup_dump_payload(struct target *t) {

	struct target_priv_dump_payload *priv = t->target_priv;

	if (priv) {
			
		ptype_cleanup(priv->prefix);
		ptype_cleanup(priv->markdir);
		free(priv);

	}

	return POM_OK;
}



int target_process_dump_payload(struct target *t, struct frame *f) {

	struct target_priv_dump_payload *priv = t->target_priv;

	struct layer *lastl = f->l;
	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	if (lastl->payload_size == 0)
		return POM_OK;

	if (!f->ce)
		conntrack_create_entry(f);


	struct target_conntrack_priv_dump_payload *cp;

	cp = conntrack_get_target_priv(t, f->ce);

	if (!cp) {


		// New connection
		cp = malloc(sizeof(struct target_conntrack_priv_dump_payload));
		memset(cp, 0, sizeof(struct target_conntrack_priv_dump_payload));

		char filename[NAME_MAX];

		char outstr[20];
		memset(outstr, 0, 20);
		// YYYYMMDD-HHMMSS-UUUUUU
		char *format = "-%Y%m%d-%H%M%S-";
		struct tm *tmp;
	        tmp = localtime((time_t*)&f->tv.tv_sec);

		strftime(outstr, 20, format, tmp);

		strcpy(filename, PTYPE_STRING_GETVAL(priv->prefix));
		strcat(filename, outstr);
		sprintf(outstr, "%u", (unsigned int)f->tv.tv_usec);
		strcat(filename, outstr);
		cp->fd = target_file_open(f->l, filename, O_RDWR | O_CREAT, 0666);

		if (cp->fd == -1) {
			free(cp);
			char errbuff[256];
			strerror_r(errno, errbuff, 256);
			pom_log(POM_LOG_ERR "Unable to open file %s for writing : %s\r\n", filename, errbuff);
			return POM_ERR;
		}

		pom_log(POM_LOG_TSHOOT "%s opened\r\n", filename);

		conntrack_add_target_priv(cp, t, f->ce, target_close_connection_dump_payload);

		cp->ce = f->ce;
		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;

	}

	if (PTYPE_BOOL_GETVAL(priv->markdir)) {
		if (f->ce->direction == CE_DIR_FWD)
			write(cp->fd, "\n> ", 3);
		else
			write(cp->fd, "\n< ", 3);
	}

	write(cp->fd, f->buff + lastl->payload_start, lastl->payload_size);

	pom_log(POM_LOG_TSHOOT "Saved %u bytes of payload\r\n", lastl->payload_size);

	return POM_OK;
};

int target_close_connection_dump_payload(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx\r\n", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_dump_payload *cp;
	cp = conntrack_priv;

	close(cp->fd);

	struct target_priv_dump_payload *priv = t->target_priv;

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;

	free(cp);

	return POM_OK;

}



