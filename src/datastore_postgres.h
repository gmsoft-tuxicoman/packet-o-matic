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


#ifndef __DATASTORE_POSTGRES_H__
#define __DATASTORE_POSTGRES_H__


#include "modules_common.h"
#include "datastore.h"

#include "ptype_string.h"

#include <libpq-fe.h>

#define DATASTORE_POSTGRES_TEMP_BUFFER_SIZE 256

struct datastore_priv_postgres {

	struct ptype *dbname;
	struct ptype *host;
	struct ptype *port;
	struct ptype *user;
	struct ptype *password;


	PGconn *connection;

};


union datastore_postgres_data {
	
	uint8_t uint8;
	uint16_t uint16;
	uint32_t uint32;
	uint64_t uint64;
	char *str;

};

struct dataset_priv_postgres {

	char *read_query_start;
	char *read_query;
	char *read_query_end;
	char *read_query_buff;
	int read_query_buff_size;

	int read_query_tot;
	int read_query_cur;
	PGresult *read_res;

	char *write_query;
	char *write_query_get_id;
	union datastore_postgres_data *write_data_buff;
	char **write_query_param_val;
	int *write_query_param_len;
	int *write_query_param_format;
	int num_fields;

};


int datastore_register_postgres(struct datastore_reg *r);
static int datastore_init_postgres(struct datastore *d);
static int datastore_open_postgres(struct datastore *d);
static int datastore_dataset_alloc_postgres(struct datastore *d, struct dataset *ds);
static int datastore_dataset_create_postgres(struct datastore *d, struct dataset *ds);
static int datastore_dataset_read_postgres(struct datastore *d, struct dataset *ds);
static int datastore_dataset_write_postgres(struct datastore *d, struct dataset *ds);
static int datastore_dataset_cleanup_postgres(struct datastore *d, struct dataset *ds);
static int datastore_close_postgres(struct datastore *d);
static int datastore_cleanup_postgres(struct datastore *d);
static int datastore_unregister_postgres(struct datastore_reg *r);


#endif
