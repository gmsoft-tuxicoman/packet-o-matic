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


#ifndef __TARGET_POP_H__
#define __TARGET_POP_H__


#include "modules_common.h"
#include "rules.h"


struct target_conntrack_priv_pop {

	int fd; ///< Must be -1 if no file is open
	int server_dir; ///< Indicates which direction is the server

	char *username;
	char *password;

	int lastcmd; ///< Last pop command received

	char *parsed_path; ///< General path of the mailbox
	char *filename; ///< Filename of an actual email

	struct conntrack_entry *ce;

	struct target_conntrack_priv_pop *next;
	struct target_conntrack_priv_pop *prev;

};

struct target_priv_pop {

	struct ptype *path;
	struct target_conntrack_priv_pop *ct_privs;

};

int target_register_pop(struct target_reg *r, struct target_functions *tg_funcs);

int target_init_pop(struct target *t);
int target_process_pop(struct target *t, struct frame *f);
int target_close_connection_pop(struct target *t, struct conntrack_entry* ce, void *conntrack_priv);
int target_close_pop(struct target *t);
int target_cleanup_pop(struct target *t);

int pop_process_line(struct target_conntrack_priv_pop *cp, char *line, int size, struct frame *f);
int pop_file_open(struct target_conntrack_priv_pop *cp, struct timeval *recvd_time);
int pop_file_close(struct target_conntrack_priv_pop *cp);
int pop_write_login_info(struct target_conntrack_priv_pop *cp, struct frame *f);

#endif