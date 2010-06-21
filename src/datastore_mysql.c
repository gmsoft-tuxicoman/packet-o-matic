/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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

#include "datastore_mysql.h"

#include "ptype_bool.h"
#include "ptype_uint8.h"
#include "ptype_uint16.h"
#include "ptype_uint32.h"
#include "ptype_uint64.h"
#include "ptype_timestamp.h"

#define MYSQL_PKID_NAME	"pkid"

#define MYSQL_PTYPE_OTHER	0
#define MYSQL_PTYPE_BOOL	1
#define MYSQL_PTYPE_UINT8	2
#define MYSQL_PTYPE_UINT16	3
#define MYSQL_PTYPE_UINT32	4
#define MYSQL_PTYPE_UINT64	5
#define MYSQL_PTYPE_STRING	6
#define MYSQL_PTYPE_TIMESTAMP	7

static struct ptype *pt_bool, *pt_uint8, *pt_uint16, *pt_uint32, *pt_uint64, *pt_string, *pt_timestamp;

int datastore_register_mysql(struct datastore_reg *r) {


	if (mysql_library_init(0, NULL, NULL)) {
		pom_log(POM_LOG_ERR "Unable to initialize the MySQL library");
		return POM_ERR;
	}

	// Allocate ptypes to keep refcount and get their id
	pt_bool = ptype_alloc("bool", NULL);
	pt_uint8 = ptype_alloc("uint8", NULL);
	pt_uint16 = ptype_alloc("uint16", NULL);
	pt_uint32 = ptype_alloc("uint32", NULL);
	pt_uint64 = ptype_alloc("uint64", NULL);
	pt_string = ptype_alloc("string", NULL);
	pt_timestamp = ptype_alloc("timestamp", NULL);
	
	if (!pt_bool || !pt_uint8 || !pt_uint16 || !pt_uint32 || !pt_uint64 || !pt_string || !pt_timestamp) {
		datastore_unregister_mysql(r);
		return POM_ERR;
	}

	datastore_register_param(r, "dbname", "pom", "Database name");
	datastore_register_param(r, "host", "localhost", "Host to connect to");
	datastore_register_param(r, "port", "0", "Port to connect to");
	datastore_register_param(r, "user", "", "User");
	datastore_register_param(r, "password", "", "Password");
	datastore_register_param(r, "unix_socket", "", "Unix socket");

	r->init = datastore_init_mysql;
	r->open = datastore_open_mysql;
	r->dataset_alloc = datastore_dataset_alloc_mysql;
	r->dataset_create = datastore_dataset_create_mysql;
	r->dataset_read = datastore_dataset_read_mysql;
	r->dataset_write = datastore_dataset_write_mysql;
	r->dataset_delete = datastore_dataset_delete_mysql;
	r->dataset_destroy = datastore_dataset_destroy_mysql;
	r->dataset_cleanup = datastore_dataset_cleanup_mysql;
	r->close = datastore_close_mysql;
	r->cleanup = datastore_cleanup_mysql;
	r->unregister = datastore_unregister_mysql;

	return POM_OK;
}


static int datastore_init_mysql(struct datastore *d) {

	struct datastore_priv_mysql *priv = malloc(sizeof(struct datastore_priv_mysql));
	memset(priv, 0, sizeof(struct datastore_priv_mysql));


	d->priv = priv;

	priv->dbname = ptype_alloc("string", NULL);
	priv->host = ptype_alloc("string", NULL);
	priv->port = ptype_alloc("uint16", NULL);
	priv->user = ptype_alloc("string", NULL);
	priv->password = ptype_alloc("string", NULL);
	priv->unix_socket = ptype_alloc("string", NULL);

	if (!priv->dbname || !priv->host || !priv->port || !priv->user || !priv->password || !priv->unix_socket) {
		datastore_cleanup_mysql(d);
		return POM_ERR;
	}

	datastore_register_param_value(d, "dbname", priv->dbname);
	datastore_register_param_value(d, "host", priv->host);
	datastore_register_param_value(d, "port", priv->port);
	datastore_register_param_value(d, "user", priv->user);
	datastore_register_param_value(d, "password", priv->password);
	datastore_register_param_value(d, "unix_socket", priv->unix_socket);

	return POM_OK;
}

static int datastore_open_mysql(struct datastore *d) {

	struct datastore_priv_mysql *priv = d->priv;

	char *dbname = PTYPE_STRING_GETVAL(priv->dbname);
	char *host = PTYPE_STRING_GETVAL(priv->host);
	unsigned int port = PTYPE_UINT16_GETVAL(priv->port);
	char *user = PTYPE_STRING_GETVAL(priv->user);
	char *pass = PTYPE_STRING_GETVAL(priv->password);
	char *unix_socket = PTYPE_STRING_GETVAL(priv->unix_socket);
	if (!strlen(unix_socket))
		unix_socket = NULL;

	priv->connection = mysql_init(NULL);

	if (!priv->connection) {
		pom_log(POM_LOG_ERR "Unable to initialize the MySQL connection");
		free(priv);
		return POM_ERR;
	}

	my_bool trueval = 1;
	mysql_options(priv->connection, MYSQL_OPT_RECONNECT, &trueval);

	if (!mysql_real_connect(priv->connection, host, user, pass, dbname, port, unix_socket, 0)) {
		pom_log(POM_LOG_ERR "Connection to database failed: %s", mysql_error(priv->connection));
		return POM_ERR;
	}

	pom_log(POM_LOG_INFO "Connected on database %s at %s", dbname, host);

	return POM_OK;

}

static int datastore_dataset_alloc_mysql(struct dataset *ds) {

	struct dataset_priv_mysql *priv = malloc(sizeof(struct dataset_priv_mysql));
	memset(priv, 0, sizeof(struct dataset_priv_mysql));

	int size = strlen("SELECT " MYSQL_PKID_NAME ", ") + strlen(" FROM ") + strlen(ds->name);
	priv->read_query = malloc(size + 1);
	strcpy(priv->read_query, "SELECT " MYSQL_PKID_NAME ", ");
	int i;
	struct datavalue *dv = ds->query_data;
	for (i = 0; dv[i].name; i++) {
		
		if (dv[i].value->type == pt_bool->type)
			dv[i].native_type = MYSQL_PTYPE_BOOL;
		else if (dv[i].value->type == pt_uint8->type)
			dv[i].native_type = MYSQL_PTYPE_UINT8;
		else if (dv[i].value->type == pt_uint16->type)
			dv[i].native_type = MYSQL_PTYPE_UINT16;
		else if (dv[i].value->type == pt_uint32->type)
			dv[i].native_type = MYSQL_PTYPE_UINT32;
		else if (dv[i].value->type == pt_uint64->type)
			dv[i].native_type = MYSQL_PTYPE_UINT64;
		else if (dv[i].value->type == pt_string->type)
			dv[i].native_type = MYSQL_PTYPE_STRING;
		else if (dv[i].value->type == pt_timestamp->type)
			 dv[i].native_type = MYSQL_PTYPE_TIMESTAMP;
		else
			dv[i].native_type = MYSQL_PTYPE_OTHER;

		size += strlen(dv[i].name) + strlen(", ");
		priv->read_query = realloc(priv->read_query, size + 1);

		strcat(priv->read_query, dv[i].name);
		if (dv[i + 1].name)
			strcat(priv->read_query, ", ");

	}
	strcat(priv->read_query, " FROM ");
	strcat(priv->read_query, ds->name);
	pom_log(POM_LOG_TSHOOT "READ QUERY : %s", priv->read_query);

	priv->read_query_buff_size = 1;
	priv->read_query_buff = malloc(2);

	size = strlen("INSERT INTO ") + strlen(ds->name) + strlen(" ( ") + strlen(" ) VALUES ( ") + strlen(" )");
	priv->write_query = malloc(size + 1);
	strcpy(priv->write_query, "INSERT INTO ");
	strcat(priv->write_query, ds->name);
	strcat(priv->write_query, " ( ");

	for (i = 0; dv[i].name; i++) {
		size += strlen(dv[i].name) + 2;
		priv->write_query = realloc(priv->write_query, size + 1);
		strcat(priv->write_query, dv[i].name);
		if (dv[i + 1].name)
			strcat(priv->write_query, ", ");
	}

	priv->num_fields = i;

	strcat(priv->write_query, " ) VALUES ( ");

	for (i = 0; dv[i].name; i++) {
		size += strlen("?, ");
		priv->write_query = realloc(priv->write_query, size + 1);
		strcat(priv->write_query, "?");
		if (dv[i + 1].name)
			strcat(priv->write_query, ", ");
	}

	strcat(priv->write_query, " )");

	pom_log(POM_LOG_TSHOOT "WRITE QUERY : %s", priv->write_query);


	priv->fields_bind = malloc(sizeof(MYSQL_BIND) * (priv->num_fields + 1));
	memset(priv->fields_bind, 0, sizeof(MYSQL_BIND) * (priv->num_fields + 1));
	
	priv->fields_len = malloc(sizeof(unsigned long) * (priv->num_fields + 1));
	memset(priv->fields_len, 0, sizeof(unsigned long) * (priv->num_fields + 1));

	MYSQL_BIND *b = priv->fields_bind;

	// Bind the PKID
	b[0].buffer_type = MYSQL_TYPE_LONGLONG;
	b[0].buffer = &ds->data_id;
	b[0].buffer_length = sizeof(ds->data_id);
	b[0].length = &priv->fields_len[0];

	// Bind the values
	
	for (i = 0; i < priv->num_fields; i++) {
		switch (dv[i].native_type) {
			case MYSQL_PTYPE_BOOL:
				b[i + 1].buffer_type = MYSQL_TYPE_LONG;
				b[i + 1].buffer = dv[i].value->value;
				b[i + 1].buffer_length = sizeof(int);
				break;
			case MYSQL_PTYPE_UINT8:
				b[i + 1].buffer_type = MYSQL_TYPE_TINY;
				b[i + 1].buffer = dv[i].value->value;
				b[i + 1].buffer_length = sizeof(uint8_t);
				break;
			case MYSQL_PTYPE_UINT16:
				b[i + 1].buffer_type = MYSQL_TYPE_SHORT;
				b[i + 1].buffer = dv[i].value->value;
				b[i + 1].buffer_length = sizeof(uint16_t);
				break;
			case MYSQL_PTYPE_UINT32:
				b[i + 1].buffer_type = MYSQL_TYPE_LONG;
				b[i + 1].buffer = dv[i].value->value;
				b[i + 1].buffer_length = sizeof(uint32_t);
				break;
			case MYSQL_PTYPE_UINT64:
				b[i + 1].buffer_type = MYSQL_TYPE_LONGLONG;
				b[i + 1].buffer = dv[i].value->value;
				b[i + 1].buffer_length = sizeof(uint64_t);
				break;
			case MYSQL_PTYPE_TIMESTAMP:
				b[i + 1].buffer_type = MYSQL_TYPE_TIMESTAMP;
				b[i + 1].buffer = malloc(sizeof(MYSQL_TIME));
				b[i + 1].buffer_length = sizeof(MYSQL_TIME);
				break;
			case MYSQL_PTYPE_STRING:
			case MYSQL_PTYPE_OTHER:
				// Do not allocate value but handle that later on
				b[i + 1].buffer_type = MYSQL_TYPE_STRING;
				b[i + 1].buffer = 0;
				b[i + 1].buffer_length = 0;
				break;

		}
		b[i + 1].length = &priv->fields_len[i + 1];
	}



	ds->priv = priv;

	return POM_OK;
}

static int datastore_dataset_create_mysql(struct dataset *ds) {

	struct datavalue *dv = ds->query_data;

	unsigned int len = strlen("CREATE TABLE ") + strlen(ds->name) + strlen(" ( " MYSQL_PKID_NAME " BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, ") + strlen(" )");

	char *query = malloc(len + 1);
	memset(query, 0, len + 1);

	strcat(query, "CREATE TABLE ");
	strcat(query, ds->name);
	strcat(query, " ( " MYSQL_PKID_NAME " BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, ");

	int i;
	for (i = 0; dv[i].name; i++) {
	
		char *type = " TEXT";
		switch (dv[i].native_type) {
			case MYSQL_PTYPE_BOOL:
				type = " BOOL";
				break;
			case MYSQL_PTYPE_UINT8:
				type = " TINYINT UNSIGNED";
				break;
			case MYSQL_PTYPE_UINT16:
				type = " SMALLINT UNSIGNED";
				break;
			case MYSQL_PTYPE_UINT32:
				type = " INT UNSIGNED";
				break;
			case MYSQL_PTYPE_UINT64:
				type = " BIGINT UNSIGNED";
				break;
			case MYSQL_PTYPE_TIMESTAMP:
				type = " TIMESTAMP";
				break;
		}

		len += strlen(dv[i].name) + strlen(type);
		if (dv[i + 1].name)
			len += strlen(", ");

		query = realloc(query, len + 1);

		strcat(query, dv[i].name);
		strcat(query, type);
		if (dv[i + 1].name)
			strcat(query, ", ");

	}

	strcat(query, " )");
	
	pom_log(POM_LOG_TSHOOT "CREATE QUERY : %s", query);

	struct datastore_priv_mysql *priv = ds->dstore->priv;

	int res = mysql_query(priv->connection, query);
	free(query);

	if (res) {
		pom_log(POM_LOG_ERR "Failed to create dataset \"%s\" in datastore %s : %s", ds->name, ds->dstore->name, mysql_error(priv->connection));
		ds->state = mysql_get_ds_state_error(priv->connection);
		return POM_ERR;
	}

	ds->state = DATASET_STATE_DONE;

	return POM_OK;
}

static int datastore_dataset_read_mysql(struct dataset *ds) {

	struct dataset_priv_mysql *priv = ds->priv;
	struct datastore_priv_mysql *dpriv = ds->dstore->priv;

	struct datavalue *dv = ds->query_data;

	if (ds->state != DATASET_STATE_MORE) {
		char *read_query = priv->read_query;

		struct datavalue_condition *qc = ds->query_cond;
		if (qc) {
			int size, new_size = priv->read_query_buff_size;

			read_query = priv->read_query_buff;

			char *string_val = NULL;
			if (dv[qc->field_id].native_type == MYSQL_PTYPE_STRING) {
				size_t len = strlen(PTYPE_STRING_GETVAL(qc->value));
				string_val = malloc((len * 2) + 1);
				mysql_real_escape_string(dpriv->connection, string_val, PTYPE_STRING_GETVAL(qc->value), len);
			}

			while (1) {
				size = new_size;
				char *op = NULL;
				switch (qc->op) {
					case PTYPE_OP_EQ:
						op = "=";
						break;
					default:
						op = ptype_get_op_sign(qc->op);
				}

				switch (dv[qc->field_id].native_type) {
					case MYSQL_PTYPE_BOOL:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query, dv[qc->field_id].name, op, PTYPE_BOOL_GETVAL(qc->value));
						break;
					case MYSQL_PTYPE_UINT8:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
						break;
					case MYSQL_PTYPE_UINT16:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query, dv[qc->field_id].name, op, PTYPE_UINT16_GETVAL(qc->value));
						break;
					case MYSQL_PTYPE_UINT32:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query, dv[qc->field_id].name, op, PTYPE_UINT32_GETVAL(qc->value));
						break;
					case MYSQL_PTYPE_UINT64:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %llu", priv->read_query, dv[qc->field_id].name, op, (unsigned long long) PTYPE_UINT64_GETVAL(qc->value));
						break;
					case MYSQL_PTYPE_STRING:
						new_size = snprintf(read_query, size, "%s WHERE %s %s '%s'", priv->read_query, dv[qc->field_id].name, op, string_val);
						break;
					default:
						pom_log(POM_LOG_ERR "Unsupported ptype in read condition");
						priv->read_query_buff = read_query;
						priv->read_query_buff_size = size;
						ds->state = DATASET_STATE_ERR;
						return POM_ERR;
				}

				if (new_size >= -1 && new_size < size)
					break;

				new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
				read_query = realloc(read_query, new_size + 1);
			}
			priv->read_query_buff = read_query;
			priv->read_query_buff_size = size;
			
			if (string_val)
				free(string_val);

		}

		
		struct datavalue_read_order *qro = ds->query_read_order;
		if (qro) {
			struct datavalue *dv = ds->query_data;
			int new_size;
			new_size = strlen(" ORDER BY ") + strlen(dv[qro->field_id].name);
			if (qro->direction)
				new_size += strlen(" DESC");

			if (read_query == priv->read_query) {
				read_query = priv->read_query_buff;
				new_size += strlen(priv->read_query);
				if (priv->read_query_buff_size < new_size) {
					read_query = realloc(read_query, new_size + 1);
					priv->read_query_buff_size = new_size;
				}
				strcpy(read_query, priv->read_query);

			} else {
				new_size += strlen(read_query);
				if (priv->read_query_buff_size < new_size) {
					read_query = realloc(read_query, new_size + 1);
					priv->read_query_buff_size = new_size;
				}

			}
			strcat(read_query, " ORDER BY ");
			strcat(read_query, dv[qro->field_id].name);
			if (qro->direction == DATASET_READ_ORDER_DESC)
				strcat(read_query, " DESC");
			priv->read_query_buff = read_query;
		}

		priv->read_stmt = mysql_stmt_init(dpriv->connection);

		if (!priv->read_stmt) {
			ds->state = mysql_get_ds_state_error(dpriv->connection);
			pom_log(POM_LOG_DEBUG "Unable to initialize the READ SQL query : %s", mysql_error(dpriv->connection));
			return POM_ERR;
		}

		int res = mysql_stmt_prepare(priv->read_stmt, read_query, strlen(read_query));
		if (res) {
			ds->state = mysql_get_ds_state_error(dpriv->connection);
			pom_log(POM_LOG_ERR "Unable to prepare the READ SQL query : %s", mysql_error(dpriv->connection));
			mysql_stmt_close(priv->read_stmt);
			priv->read_stmt = NULL;
			return POM_ERR;
		}

		res = mysql_stmt_execute(priv->read_stmt);
		if (res) {
			ds->state = mysql_get_ds_state_error(dpriv->connection);
			pom_log(POM_LOG_ERR "Unable to execute the READ SQL query : %s", mysql_error(dpriv->connection));
			mysql_stmt_close(priv->read_stmt);
			priv->read_stmt = NULL;
			return POM_ERR;
		}

	}


	MYSQL_BIND *b = priv->fields_bind;
	unsigned long *lengths = priv->fields_len;


	if (mysql_stmt_bind_result(priv->read_stmt, b)) {
		ds->state = mysql_get_ds_state_error(dpriv->connection);
		pom_log(POM_LOG_ERR "Unable bind the to result set of the READ SQL query : %s", mysql_error(dpriv->connection));
		mysql_stmt_close(priv->read_stmt);
		priv->read_stmt = NULL;
		return POM_ERR;
	}

	int res = mysql_stmt_fetch(priv->read_stmt);
	if (res == MYSQL_NO_DATA) {
		ds->state = DATASET_STATE_DONE;
		mysql_stmt_close(priv->read_stmt);
		priv->read_stmt = NULL;
		return POM_OK;
	} else if (res == MYSQL_DATA_TRUNCATED) {
		// Fetch strings
		int i;
		for (i = 0; i < priv->num_fields; i++) {
			if (dv[i].native_type != MYSQL_PTYPE_STRING ||
				dv[i].native_type == MYSQL_PTYPE_OTHER)
				continue;

			char *data = malloc(lengths[i + 1] + 1);
			memset(data, 0, lengths[i + 1] + 1);
			b[i + 1].buffer = data;
			b[i + 1].buffer_length = lengths[i + 1];

			if (mysql_stmt_fetch_column(priv->read_stmt, &b[i + 1], i + 1, 0)) {
				pom_log(POM_LOG_ERR "Data truncated or error while refetching fields : %s", mysql_error(dpriv->connection));
				ds->state = mysql_get_ds_state_error(dpriv->connection);
				mysql_stmt_close(priv->read_stmt);
				priv->read_stmt = NULL;
				int j;
				for (j = 0; j < priv->num_fields; j++) {
					if (dv[j].native_type == MYSQL_PTYPE_STRING ||
						dv[j].native_type == MYSQL_PTYPE_OTHER)
						free(b[j + 1].buffer);
				}
				return POM_ERR;
			}

			if (dv[i].native_type == MYSQL_PTYPE_STRING) {
				PTYPE_STRING_SETVAL_P(dv[i].value, b[i + 1].buffer);
			} else if (dv[i].native_type == MYSQL_PTYPE_OTHER) {
				if (ptype_parse_val(dv[i].value, b[i + 1].buffer) != POM_OK) {
					ds->state = DATASET_STATE_ERR;
					pom_log(POM_LOG_ERR "Unable to parse result value : \"%s\"", b[i + 1].buffer);
					free(b[i + 1].buffer);
					mysql_stmt_close(priv->read_stmt);
					priv->read_stmt = NULL;
					int j;
					for (j = i; j < priv->num_fields; j++) {
						if (dv[j].native_type == MYSQL_PTYPE_STRING ||
							dv[j].native_type == MYSQL_PTYPE_OTHER)
							free(b[j + 1].buffer);
					}
					return POM_ERR;
				}
				free(b[i + 1].buffer);
			}

			// restore old value
			b[i + 1].buffer = 0;
			b[i + 1].buffer_length = 0;
			lengths[i + 1] = 0;
		}

	} else {
		pom_log(POM_LOG_ERR "Error while reading data from dataset %s : %s", ds->name, mysql_error(dpriv->connection));
		ds->state = mysql_get_ds_state_error(dpriv->connection);
		mysql_stmt_close(priv->read_stmt);
		priv->read_stmt = NULL;
		return POM_ERR;
	}
	
	ds->state = DATASET_STATE_MORE;

	return POM_OK;
}

static int datastore_dataset_write_mysql(struct dataset *ds) {


	struct datastore_priv_mysql *dpriv = ds->dstore->priv;
	struct dataset_priv_mysql *priv = ds->priv;

	MYSQL_BIND *b = &priv->fields_bind[1]; // skip pkid

	if (!priv->write_stmt) {
		priv->write_stmt = mysql_stmt_init(dpriv->connection);
		if (!priv->write_stmt) {
			ds->state = mysql_get_ds_state_error(dpriv->connection);
			pom_log(POM_LOG_ERR "Unable to initialize the WRITE SQL query : %s", mysql_error(dpriv->connection));
			return POM_ERR;
		}

		if (mysql_stmt_prepare(priv->write_stmt, priv->write_query, strlen(priv->write_query))) {
			ds->state = mysql_get_ds_state_error(dpriv->connection);
			pom_log(POM_LOG_ERR "Unable to prepare the WRITE SQL query : %s", mysql_error(dpriv->connection));
			mysql_stmt_close(priv->write_stmt);
			priv->write_stmt = NULL;
			return POM_ERR;
		}
		

		unsigned int param_count = mysql_stmt_param_count(priv->write_stmt);
		if (param_count != priv->num_fields) {
			ds->state = mysql_get_ds_state_error(dpriv->connection);
			pom_log(POM_LOG_ERR "Parameter count doesn't match the expected value : %u != %u", param_count, priv->num_fields);
			mysql_stmt_close(priv->write_stmt);
			priv->write_stmt = NULL;
			return POM_ERR;
		}

	}


	struct datavalue *dv = ds->query_data;
	int i;
	for (i = 0; dv[i].name; i++) {

		// Handle timestamps
		if (dv[i].native_type == MYSQL_PTYPE_TIMESTAMP) {
			MYSQL_TIME *ts = b[i].buffer;
			time_t my_time = PTYPE_TIMESTAMP_GETVAL(dv[i].value);
			struct tm split_time;
			
			localtime_r(&my_time, &split_time);

			ts->year = split_time.tm_year + 1900;
			ts->month = split_time.tm_mon + 1;
			ts->day = split_time.tm_mday;

			ts->hour = split_time.tm_hour;
			ts->minute = split_time.tm_min;
			ts->second = split_time.tm_sec;
			continue;
		}


		// Handle type string and other
		char *value = NULL;
		if (dv[i].native_type == MYSQL_PTYPE_STRING) {
			value = PTYPE_STRING_GETVAL(dv[i].value);
		} else if (dv[i].native_type == MYSQL_PTYPE_OTHER) {
			value = ptype_print_val_alloc(dv[i].value);
		} else {
			continue;
		}

		b[i].buffer = value;
		unsigned long len = 0;
		if (value) 
			len = strlen(value);
		b[i].buffer_length = len;
		*b[i].length = len;
	}

	// We need to rebind the params as we changed the buffers address
	if (mysql_stmt_bind_param(priv->write_stmt, b)) {
		ds->state = mysql_get_ds_state_error(dpriv->connection);
		pom_log(POM_LOG_ERR "Unable to bind the parameters for the WRITE SQL query : %s", mysql_error(dpriv->connection));
		mysql_stmt_close(priv->write_stmt);
		priv->write_stmt = NULL;
		return POM_ERR;
	}

	if (mysql_stmt_execute(priv->write_stmt)) {
		ds->state = mysql_get_ds_state_error(dpriv->connection);
		pom_log(POM_LOG_ERR "Unable to execute the WRITE SQL query : %s", mysql_error(dpriv->connection));
		mysql_stmt_close(priv->write_stmt);
		priv->write_stmt = NULL;
		return POM_ERR;
	}

	// Free allocated stuff for PTYPE_OTHER and restore old values
	for (i = 0; dv[i].name; i++) {
		if (dv[i].native_type == MYSQL_PTYPE_OTHER)
			free(b[i].buffer);
		if (dv[i].native_type == MYSQL_PTYPE_STRING ||
			dv[i].native_type == MYSQL_PTYPE_OTHER) {
			b[i].buffer = 0;
			b[i].buffer_length = 0;
			*b[i].length = 0;
		}
	}
	

	ds->data_id = mysql_insert_id(dpriv->connection);

	ds->state = DATASET_STATE_DONE;

	return POM_OK;
}

static int datastore_dataset_delete_mysql(struct dataset* ds) {

	struct datastore_priv_mysql *priv = ds->dstore->priv;
	int size, new_size = 64;
	char *query = malloc(new_size + 1);
	struct datavalue_condition *qc = ds->query_cond;
	if (qc) {
		struct datavalue *dv = ds->query_data;

		char *string_val = NULL;
		if (dv[qc->field_id].native_type == MYSQL_PTYPE_STRING) {
			size_t len = strlen(PTYPE_STRING_GETVAL(qc->value));
			string_val = malloc((len * 2) + 1);
			mysql_real_escape_string(priv->connection, string_val, PTYPE_STRING_GETVAL(qc->value), len);
		}

		while (1) {
			size = new_size;
			char *op = NULL;
			switch (qc->op) {
				case PTYPE_OP_EQ:
					op = "=";
					break;
				default:
					op = ptype_get_op_sign(qc->op);
					break;

			}
			switch (dv[qc->field_id].native_type) {
				case MYSQL_PTYPE_BOOL:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
					break;
				case MYSQL_PTYPE_UINT8:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
					break;
				case MYSQL_PTYPE_UINT16:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT16_GETVAL(qc->value));
					break;
				case MYSQL_PTYPE_UINT32:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT32_GETVAL(qc->value));
					break;
				case MYSQL_PTYPE_UINT64:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %llu", ds->name, dv[qc->field_id].name, op, (unsigned long long) PTYPE_UINT64_GETVAL(qc->value));
					break;
				case MYSQL_PTYPE_STRING:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s '%s'", ds->name, dv[qc->field_id].name, op, string_val);
					break;
				default:
					pom_log(POM_LOG_ERR "Unsupported ptype in query condition");
					return POM_ERR;
			}
			if (new_size >= -1 && new_size < size)
				break;
			
			new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
			query = realloc(query, new_size + 1);

		}
		
		if (string_val)
			free(string_val);

	} else {

		do {
			size = new_size;
			new_size = snprintf(query, size, "DELETE FROM %s", ds->name);
			new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
			query = realloc(query, new_size + 1);
		} while (new_size > size);

	}

	int res = mysql_query(priv->connection, query);
	free(query);

	if (res) {
		pom_log(POM_LOG_ERR "Failed to delete from dataset \"%s\" in datastore %s : %s", ds->name, ds->dstore->name, mysql_error(priv->connection));
		ds->state = mysql_get_ds_state_error(priv->connection);
		return POM_ERR;
	}

	ds->state = DATASET_STATE_DONE;


	return res;
}

static int datastore_dataset_destroy_mysql(struct dataset *ds) {

	struct datastore_priv_mysql *priv = ds->dstore->priv;
	int size = 0, new_size = 32;
	char *query = malloc(new_size + 1);
	do {
		size = new_size;
		new_size = snprintf(query, size, "DROP TABLE %s", ds->name);
		new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
		query = realloc(query, new_size + 1);
	} while (new_size > size);

	int res = mysql_query(priv->connection, query);
	free(query);

	if (res) {
		pom_log(POM_LOG_ERR "Failed to destroy the dataset \"%s\" in datastore %s : %s", ds->name, ds->dstore->name, mysql_error(priv->connection));
		ds->state = mysql_get_ds_state_error(priv->connection);
		return POM_ERR;
	}

	ds->state = DATASET_STATE_DONE;

	return res;
}

static int datastore_dataset_cleanup_mysql(struct dataset *ds) {

	struct dataset_priv_mysql *priv = ds->priv;
	free(priv->read_query);
	free(priv->read_query_buff);
	if (priv->read_stmt)
		mysql_stmt_close(priv->read_stmt);
	free(priv->write_query);
	if (priv->write_stmt)
		mysql_stmt_close(priv->write_stmt);
	free(priv->fields_bind);
	free(priv->fields_len);
	free(priv);

	return POM_OK;

}


static int datastore_close_mysql(struct datastore *d) {

	struct datastore_priv_mysql *priv = d->priv;

	mysql_close(priv->connection);
	priv->connection = NULL;
	pom_log(POM_LOG_INFO "Connection to the database closed");

	return POM_OK;
}

static int datastore_cleanup_mysql(struct datastore *d) {

	struct datastore_priv_mysql *priv = d->priv;

	if (priv) {
		ptype_cleanup(priv->dbname);
		ptype_cleanup(priv->host);
		ptype_cleanup(priv->port);
		ptype_cleanup(priv->user);
		ptype_cleanup(priv->password);
		ptype_cleanup(priv->unix_socket);
		free(d->priv);
		d->priv = NULL;
	}

	return POM_OK;
}

static int datastore_unregister_mysql(struct datastore_reg *r) {

	mysql_library_end();

	ptype_cleanup(pt_bool);
	ptype_cleanup(pt_uint8);
	ptype_cleanup(pt_uint16);
	ptype_cleanup(pt_uint32);
	ptype_cleanup(pt_uint64);
	ptype_cleanup(pt_string);
	ptype_cleanup(pt_timestamp);

	return POM_OK;

}

static int mysql_get_ds_state_error(MYSQL *connection) {

	const char *errcode = mysql_sqlstate(connection);

	switch(*errcode) { // Select correct state depending on error class
		case '2':
		case '3':
		case '4':
			// Likely to be a dataset specific error
			return DATASET_STATE_ERR;
	}

	return DATASET_STATE_DATASTORE_ERR;

}

