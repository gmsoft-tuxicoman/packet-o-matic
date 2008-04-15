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


#ifndef __TARGET_TFTP_H__
#define __TARGET_TFTP_H__


#include "modules_common.h"
#include "rules.h"

#define TFTP_CONNECTION_TIMER 120

struct target_connection_priv_tftp {

	int fd; ///< Must be -1 if no file is open

	char filename[NAME_MAX]; ///< Filename of an actual email
	int last_block; ///< Last recevied block

	struct conntrack_entry *ce;
};


struct target_conntrack_priv_tftp {

	struct conntrack_entry *ce;
	struct target_connection_priv_tftp *conn;
	char *parsed_path; ///< General path of the mailbox

	struct target_conntrack_priv_tftp *next;
	struct target_conntrack_priv_tftp *prev;

};


struct target_priv_tftp {

	struct ptype *path;
	struct target_conntrack_priv_tftp *ct_privs;

};

int target_register_tftp(struct target_reg *r);

int target_init_tftp(struct target *t);
int target_process_tftp(struct target *t, struct frame *f);
int target_close_connection_tftp(struct target *t, struct conntrack_entry* ce, void *conntrack_priv);
int target_close_tftp(struct target *t);
int target_cleanup_tftp(struct target *t);

int tftp_process_packet(struct target *t, struct conntrack_entry *ce, struct target_conntrack_priv_tftp *cp, char *line, int size, struct frame *f);
int tftp_file_open(struct target_conntrack_priv_tftp *cp, struct timeval *recvd_time);
int tftp_file_close(struct target_conntrack_priv_tftp *cp);

#endif
