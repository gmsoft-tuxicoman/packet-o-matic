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


#ifndef __DATASTORE_SQLITE_H__
#define __DATASTORE_SQLITE_H__


#include "modules_common.h"
#include "datastore.h"

#include "ptype_string.h"

#include <sqlite3.h>

#define DATASTORE_SQLITE_TEMP_BUFFER_SIZE 256

struct dataset_priv_sqlite {

	char *read_query;
	char *read_query_buff;
	int read_query_buff_size;
	sqlite3_stmt *read_stmt;

	char *write_query;
	sqlite3_stmt *write_stmt;

};

struct datastore_priv_sqlite {

	struct ptype *dbfile;

	sqlite3 *db;

};

int datastore_register_sqlite(struct datastore_reg *r);
static int datastore_init_sqlite(struct datastore *d);
static int datastore_open_sqlite(struct datastore *d);
static int datastore_dataset_alloc_sqlite(struct dataset *ds);
static int datastore_dataset_create_sqlite(struct dataset *ds);
static int datastore_dataset_read_sqlite(struct dataset *ds);
static int datastore_dataset_write_sqlite(struct dataset *ds);
static int datastore_dataset_cleanup_sqlite(struct dataset *ds);
static int datastore_close_sqlite(struct datastore *d);
static int datastore_cleanup_sqlite(struct datastore *d);
static int datastore_unregister_sqlite(struct datastore_reg *r);

static int sqlite_get_ds_state_error(int res);


#endif
