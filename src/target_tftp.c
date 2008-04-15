/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2008 Guy Martin <gmsoft@tuxicoman.be>
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

#include "target_tftp.h"
#include "expectation.h"
#include "ptype_bool.h"
#include "ptype_string.h"

unsigned int match_undefined_id;
struct target_mode *mode_default;

int target_register_tftp(struct target_reg *r) {

	r->init = target_init_tftp;
	r->process = target_process_tftp;
	r->close = target_close_tftp;
	r->cleanup = target_cleanup_tftp;

	match_undefined_id = match_register("undefined");

	mode_default = target_register_mode(r->type, "dump", "Dump emails into separate maildir folders");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "path", "/tmp/", "Path of the maildir folder used to save the emails");

	return POM_OK;

}

int target_init_tftp(struct target *t) {

	struct target_priv_tftp *priv = malloc(sizeof(struct target_priv_tftp));
	memset(priv, 0, sizeof(struct target_priv_tftp));

	t->target_priv = priv;

	priv->path = ptype_alloc("string", NULL);

	if (!priv->path) {
		target_cleanup_tftp(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "path", priv->path);

	return POM_OK;
}


int target_close_tftp(struct target *t) {

	struct target_priv_tftp *priv = t->target_priv;

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_tftp(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

int target_cleanup_tftp(struct target *t) {

	struct target_priv_tftp *priv = t->target_priv;

	if (priv) {
			
		ptype_cleanup(priv->path);
		free(priv);

	}

	return POM_OK;
}



int target_process_tftp(struct target *t, struct frame *f) {

	struct target_priv_tftp *priv = t->target_priv;

	struct layer *lastl = f->l;
	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	struct conntrack_entry *ce = f->ce;

	if (!ce) {
		conntrack_create_entry(f); ce = f->ce;
	} 

	struct target_conntrack_priv_tftp *cp;

	cp = conntrack_get_target_priv(t, ce);

	if (!cp) {


		// New connection
		cp = malloc(sizeof(struct target_conntrack_priv_tftp));
		memset(cp, 0, sizeof(struct target_conntrack_priv_tftp));

		char tmp[NAME_MAX + 1];
		memset(tmp, 0, sizeof(tmp));
		layer_field_parse(f->l, PTYPE_STRING_GETVAL(priv->path), tmp, NAME_MAX);
		cp->parsed_path = malloc(strlen(tmp) + 3);
		strcpy(cp->parsed_path, tmp);
		if (*(cp->parsed_path + strlen(cp->parsed_path) - 1) != '/')
			strcat(cp->parsed_path, "/");

		conntrack_add_target_priv(cp, t, ce, target_close_connection_tftp);

		cp->ce = ce;
		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;
	
	
	}

	if (lastl->payload_size == 0)
		return POM_OK;

	char* payload = f->buff + lastl->payload_start;

	return tftp_process_packet(t, ce, cp, payload, lastl->payload_size, f);

};

int tftp_process_packet(struct target *t, struct conntrack_entry *ce, struct target_conntrack_priv_tftp *cp, char *payload, int size, struct frame *f) {

	enum tftp_opcodes {
		tftp_rrq = 1,
		tftp_wrq,
		tftp_data,
		tftp_ack,
		tftp_error,
	};

	struct target_priv_tftp *priv = t->target_priv;

	uint16_t opcode = ntohs(*((uint16_t*)payload));
	payload += sizeof(uint16_t);
	size -= sizeof(uint16_t);

	switch (opcode) {
		case tftp_rrq: 
		case tftp_wrq: {
			struct target_conntrack_priv_tftp *new_cp;
			new_cp = malloc(sizeof(struct target_conntrack_priv_tftp));
			memset(new_cp, 0, sizeof(struct target_conntrack_priv_tftp));
			new_cp->parsed_path = malloc(strlen(cp->parsed_path) + 1);
			strcpy(new_cp->parsed_path, cp->parsed_path);

			new_cp->next = priv->ct_privs;
			priv->ct_privs->prev = new_cp;
			priv->ct_privs = new_cp;

			struct target_connection_priv_tftp *conn;
			conn = malloc(sizeof(struct target_connection_priv_tftp));
			memset(conn, 0, sizeof(struct target_connection_priv_tftp));

			new_cp->conn = conn;

			conn->fd = -1;

			int max = NAME_MAX;
			if (size - 2 < max)
				max = size -2;
			strncpy(conn->filename, payload, max - 2);
			payload += strlen(conn->filename) + 1;

			struct expectation_list *expt  = expectation_alloc(f, t, ce, EXPT_DIR_REV);

			// Now look for last layer
			struct expectation_node *n = expt->n;
			while (n->next)
				n = n->next;

			// Make sure we ignore the source
			struct expectation_field *fld = n->fields;
			while (fld) {
				if (!strcmp(fld->name, "sport")) {
					fld->op = EXPT_OP_IGNORE;
					break;
				}
				fld = fld->next;
			}

			expectation_set_target_priv(expt, new_cp, target_close_connection_tftp);

			if (expectation_add(expt, TFTP_CONNECTION_TIMER) == POM_ERR) {
				free(new_cp->parsed_path);
				free(new_cp);
				return POM_ERR;
			}

			break;
		}
		case tftp_data: {
	
			struct target_connection_priv_tftp *conn;
			conn = cp->conn;
			cp->ce = ce;

			uint16_t block_id = ntohs(*((uint16_t*)(payload)));
			payload += sizeof(uint16_t);
			size -= sizeof(uint16_t);
			if (!*conn->filename)
				sprintf(conn->filename, "%u.%u", (unsigned int)f->tv.tv_sec, (unsigned int)f->tv.tv_usec);

			if (conn->fd == -1 && tftp_file_open(cp, &f->tv) == POM_ERR)
						return POM_ERR;

			if (block_id <= conn->last_block)
				break;

			conn->last_block++;

			while (conn->last_block < block_id) {
				pom_log(POM_LOG_DEBUG "TFTP data block %u missed. Padding with 512 bytes\r\n", conn->last_block);
				char missed[512];
				memset(missed, 0, sizeof(missed));
				write(conn->fd, missed, sizeof(missed));
				conn->last_block++;
			}

			write(conn->fd, payload, size);

			if (size < 512)
				tftp_file_close(cp);
			break;
		}
		case tftp_ack:
			break;
		case tftp_error:
			if (cp->conn) {
				if (cp->conn->fd)
					tftp_file_close(cp);
				if (*cp->conn->filename)
					*cp->conn->filename = 0;
			}
			break;

	}

	return POM_OK;
}


int target_close_connection_tftp(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {


	struct target_conntrack_priv_tftp *cp;
	cp = conntrack_priv;

	struct target_connection_priv_tftp *conn = cp->conn;

	if (conn) {
		if (conn->fd != -1)
			tftp_file_close(cp);
		free(conn);
	}

	if (cp->parsed_path)
		free(cp->parsed_path);

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx\r\n", (unsigned long) conntrack_priv);
	struct target_priv_tftp *priv = t->target_priv;

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;

	free(cp);

	return POM_OK;

}

int tftp_file_open(struct target_conntrack_priv_tftp *cp, struct timeval *recvd_time) {

	char final_name[NAME_MAX + 1];

	struct target_connection_priv_tftp *conn = cp->conn;

	strncpy(final_name, cp->parsed_path, NAME_MAX);
	strncat(final_name, conn->filename, NAME_MAX - strlen(final_name));

	conn->fd = target_file_open(NULL, final_name, O_RDWR | O_CREAT, 0666);

	if (conn->fd == -1) {
		char errbuff[256];
		strerror_r(errno, errbuff, sizeof(errbuff));
		pom_log(POM_LOG_ERR "Unable to open file %s for writing : %s\r\n", final_name, errbuff);
		return POM_ERR;
	}

	pom_log(POM_LOG_TSHOOT "TFTP : %s opened\r\n", final_name);

	return POM_OK;
}

int tftp_file_close(struct target_conntrack_priv_tftp *cp) {

	struct target_connection_priv_tftp *conn = cp->conn;

	if (conn->fd == -1)
		return POM_ERR;
	close(conn->fd);
	conn->fd = -1;
	pom_log(POM_LOG_TSHOOT "TFTP : %s closed\r\n", conn->filename);
	*conn->filename = 0;

	return POM_OK;

}
