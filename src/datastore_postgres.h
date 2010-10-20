/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2010 Guy Martin <gmsoft@tuxicoman.be>
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


// A few defs usefull for timestamps
#define POSTGRES_EPOCH_JDATE	2451545 
#define UNIX_EPOCH_JDATE	2440588 
#define SECS_PER_DAY		86400

struct datastore_priv_postgres {

	struct ptype *dbname;
	struct ptype *host;
	struct ptype *port;
	struct ptype *user;
	struct ptype *password;

	char *conninfo; // Connection string

	PGconn *connection;

	int integer_datetimes; // True if postgres server has timestamps as int64

};


union datastore_postgres_data {
	
	uint8_t uint8;
	uint16_t uint16;
	uint32_t uint32;
	uint64_t uint64;
	int64_t int64;
	double dfloat;
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
static int datastore_dataset_alloc_postgres(struct dataset *ds);
static int datastore_dataset_create_postgres(struct dataset *ds);
static int datastore_dataset_read_postgres(struct dataset *ds);
static int datastore_dataset_write_postgres( struct dataset *ds);
static int datastore_dataset_delete_postgres( struct dataset *ds);
static int datastore_dataset_destroy_postgres(struct dataset *ds);
static int datastore_dataset_cleanup_postgres(struct dataset *ds);
static int datastore_close_postgres(struct datastore *d);
static int datastore_cleanup_postgres(struct datastore *d);
static int datastore_unregister_postgres(struct datastore_reg *r);

static int datastore_check_utf8_postgres(unsigned char *data, int len);
static int postgres_exec(struct dataset *ds, const char *query);
static int postgres_reconnect(struct datastore_priv_postgres *priv);
static int postgres_get_ds_state_error(struct dataset *ds, PGresult *res);
static void postgres_notice_processor(void *arg, const char *message);

// Functions used to swap a double value
#if BYTE_ORDER == BIG_ENDIAN
#define htond(x, y)	memcpy(y, x, 8)
#define ntohd(x, y)	memcpy(y, x, 8)
#elif BYTE_ORDER == LITTLE_ENDIAN
#define htond(x, y)	vswap64(x, y)
#define ntohd(x, y)	vswap64(x, y)
static void vswap64(void *in, void *out);
#else
#error "Please define byte ordering"
#endif


#endif
