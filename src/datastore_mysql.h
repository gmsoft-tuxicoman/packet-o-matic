/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2009 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __DATASTORE_MYSQL_H__
#define __DATASTORE_MYSQL_H__


#include "modules_common.h"
#include "datastore.h"

#include "ptype_string.h"

#include <mysql/mysql.h>

struct datastore_priv_mysql {

	struct ptype *dbname;
	struct ptype *host;
	struct ptype *port;
	struct ptype *user;
	struct ptype *password;
	struct ptype *unix_socket;

	MYSQL *connection;

};

struct dataset_priv_mysql {

	char *read_query;
	char *read_query_buff;
	int read_query_buff_size;

	MYSQL_STMT *read_stmt;
	unsigned long read_column;

	char *write_query;
	MYSQL_STMT *write_stmt;

	MYSQL_BIND *fields_bind;
	unsigned long *fields_len;

	int num_fields;

};


int datastore_register_mysql(struct datastore_reg *r);
static int datastore_init_mysql(struct datastore *d);
static int datastore_open_mysql(struct datastore *d);
static int datastore_dataset_alloc_mysql(struct dataset *ds);
static int datastore_dataset_create_mysql(struct dataset *ds);
static int datastore_dataset_read_mysql(struct dataset *ds);
static int datastore_dataset_write_mysql( struct dataset *ds);
static int datastore_dataset_cleanup_mysql(struct dataset *ds);
static int datastore_close_mysql(struct datastore *d);
static int datastore_cleanup_mysql(struct datastore *d);
static int datastore_unregister_mysql(struct datastore_reg *r);

static int mysql_get_ds_state_error(MYSQL *connection);

#endif
