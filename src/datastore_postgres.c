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

#include "datastore_postgres.h"

#include "ptype_bool.h"
#include "ptype_uint8.h"
#include "ptype_uint16.h"
#include "ptype_uint32.h"
#include "ptype_uint64.h"
#include "ptype_timestamp.h"

#define POSTGRES_PKID_NAME	"pkid"

#define POSTGRES_PTYPE_OTHER		0
#define POSTGRES_PTYPE_BOOL		1
#define POSTGRES_PTYPE_UINT8		2
#define POSTGRES_PTYPE_UINT16		3
#define POSTGRES_PTYPE_UINT32		4
#define POSTGRES_PTYPE_UINT64		5
#define POSTGRES_PTYPE_STRING		6
#define POSTGRES_PTYPE_TIMESTAMP	7

static struct ptype *pt_bool, *pt_uint8, *pt_uint16, *pt_uint32, *pt_uint64, *pt_string, *pt_timestamp;

int datastore_register_postgres(struct datastore_reg *r) {

	// Allocate ptypes to keep refcount and get their id
	pt_bool = ptype_alloc("bool", NULL);
	pt_uint8 = ptype_alloc("uint8", NULL);
	pt_uint16 = ptype_alloc("uint16", NULL);
	pt_uint32 = ptype_alloc("uint32", NULL);
	pt_uint64 = ptype_alloc("uint64", NULL);
	pt_string = ptype_alloc("string", NULL);
	pt_timestamp = ptype_alloc("timestamp", NULL);
	
	if (!pt_bool || !pt_uint8 || !pt_uint16 || !pt_uint32 || !pt_uint64 || !pt_string || !pt_timestamp) {
		datastore_unregister_postgres(r);
		return POM_ERR;
	}

	datastore_register_param(r, "dbname", "pom", "Database name");
	datastore_register_param(r, "host", "localhost", "Host to connect to");
	datastore_register_param(r, "port", "5432", "Port to connect to");
	datastore_register_param(r, "user", "", "User");
	datastore_register_param(r, "password", "", "Password");

	r->init = datastore_init_postgres;
	r->open = datastore_open_postgres;
	r->dataset_alloc = datastore_dataset_alloc_postgres;
	r->dataset_create = datastore_dataset_create_postgres;
	r->dataset_read = datastore_dataset_read_postgres;
	r->dataset_write = datastore_dataset_write_postgres;
	r->dataset_delete = datastore_dataset_delete_postgres;
	r->dataset_destroy = datastore_dataset_destroy_postgres;
	r->dataset_cleanup = datastore_dataset_cleanup_postgres;
	r->close = datastore_close_postgres;
	r->cleanup = datastore_cleanup_postgres;
	r->unregister = datastore_unregister_postgres;

	return POM_OK;
}


static int datastore_init_postgres(struct datastore *d) {

	struct datastore_priv_postgres *priv = malloc(sizeof(struct datastore_priv_postgres));
	memset(priv, 0, sizeof(struct datastore_priv_postgres));

	d->priv = priv;

	priv->dbname = ptype_alloc("string", NULL);
	priv->host = ptype_alloc("string", NULL);
	priv->port = ptype_alloc("string", NULL);
	priv->user = ptype_alloc("string", NULL);
	priv->password = ptype_alloc("string", NULL);

	if (!priv->dbname || !priv->host || !priv->port || !priv->user || !priv->password) {
		datastore_cleanup_postgres(d);
		return POM_ERR;
	}

	datastore_register_param_value(d, "dbname", priv->dbname);
	datastore_register_param_value(d, "host", priv->host);
	datastore_register_param_value(d, "port", priv->port);
	datastore_register_param_value(d, "user", priv->user);
	datastore_register_param_value(d, "password", priv->password);

	return POM_OK;
}

static int datastore_open_postgres(struct datastore *d) {

	struct datastore_priv_postgres *priv = d->priv;

	char *conninfo = NULL;

	char *dbname = malloc((strlen(PTYPE_STRING_GETVAL(priv->dbname)) * 2) + 1);
	PQescapeString(dbname, PTYPE_STRING_GETVAL(priv->dbname), strlen(PTYPE_STRING_GETVAL(priv->dbname)));
	
	unsigned int len = strlen("dbname='") + strlen(dbname) + strlen("'");
	conninfo = malloc(len + 1);
	memset(conninfo, 0, len + 1);

	// DB name
	strcpy(conninfo, "dbname='");
	strcat(conninfo, dbname);
	strcat(conninfo, "'");
	free(dbname);

	char *host = PTYPE_STRING_GETVAL(priv->host);
	if (host && *host) {
		char *ehost = malloc((strlen(host) * 2) + 1);
		PQescapeString(ehost, host, strlen(host));
		len += strlen(" host='") + strlen(ehost) + strlen("'");
		conninfo = realloc(conninfo, len + 1);
		strcat(conninfo, " host='");
		strcat(conninfo, ehost);
		strcat(conninfo, "'");
		free(ehost);
	}

	char *port = PTYPE_STRING_GETVAL(priv->port);
	if (port && *port) {
		char *eport = malloc((strlen(port) * 2) + 1);
		PQescapeString(eport, port, strlen(port));
		len += strlen(" port='") + strlen(eport) + strlen("'");
		conninfo = realloc(conninfo, len + 1);
		strcat(conninfo, " port='");
		strcat(conninfo, eport);
		strcat(conninfo, "'");
		free(eport);
	}


	char *user = PTYPE_STRING_GETVAL(priv->user);
	if (user && *user) {
		char *euser = malloc((strlen(user) * 2) + 1);
		PQescapeString(euser, user, strlen(user));
		len += strlen(" user='") + strlen(euser) + strlen("'");
		conninfo = realloc(conninfo, len + 1);
		strcat(conninfo, " user='");
		strcat(conninfo, euser);
		strcat(conninfo, "'");
		free(euser);
	}

	char *pass = PTYPE_STRING_GETVAL(priv->password);
	if (pass && *pass) {
		char *epass = malloc((strlen(pass) * 2) + 1);
		PQescapeString(epass, pass, strlen(pass));
		len += strlen(" password='") + strlen(epass) + strlen("'");
		conninfo = realloc(conninfo, len + 1);
		strcat(conninfo, " password='");
		strcat(conninfo, epass);
		strcat(conninfo, "'");
		free(epass);
	}


	priv->connection = PQconnectdb(conninfo);

	if (PQstatus(priv->connection) != CONNECTION_OK) {
		char *error = PQerrorMessage(priv->connection);
		char *br = strchr(error, '\n');
		if (br) *br = 0;
		pom_log(POM_LOG_ERR "Connection to database failed: %s", error);
		PQfinish(priv->connection);
		priv->connection = NULL;
		free(conninfo);
		return POM_ERR;
	}
	PQsetNoticeProcessor(priv->connection, postgres_notice_processor, NULL);

	priv->conninfo = conninfo;

	const char *integer_datetimes = PQparameterStatus(priv->connection, "integer_datetimes");
	if (!integer_datetimes) {
		pom_log(POM_LOG_INFO "Unable to determine binary format for TIMESTAMP fields");
		free(priv->conninfo);
		PQfinish(priv->connection);
		priv->connection = NULL;
		return POM_ERR;
	}

	if (!strcmp(integer_datetimes, "on"))
		priv->integer_datetimes = 1;
	else
		priv->integer_datetimes = 0;

	pom_log(POM_LOG_INFO "Connected on database %s at %s", PTYPE_STRING_GETVAL(priv->dbname), PTYPE_STRING_GETVAL(priv->host));

	return POM_OK;

}

static int datastore_dataset_alloc_postgres(struct dataset *ds) {

	struct dataset_priv_postgres *priv = malloc(sizeof(struct dataset_priv_postgres));
	memset(priv, 0, sizeof(struct dataset_priv_postgres));

	int size = 0, new_size = 1;
	priv->read_query_start = malloc(new_size + 1);
	
	do {
		size = new_size;
		new_size = snprintf(priv->read_query_start, size, "DECLARE %s_cur BINARY CURSOR FOR SELECT " POSTGRES_PKID_NAME ", ", ds->name);
		new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
		priv->read_query_start = realloc(priv->read_query_start, new_size + 1);
	} while (new_size > size);

	int i;
	struct datavalue *dv = ds->query_data;
	for (i = 0; dv[i].name; i++) {
		
		if (dv[i].value->type == pt_bool->type)
			dv[i].native_type = POSTGRES_PTYPE_BOOL;
		else if (dv[i].value->type == pt_uint8->type)
			dv[i].native_type = POSTGRES_PTYPE_UINT8;
		else if (dv[i].value->type == pt_uint16->type)
			dv[i].native_type = POSTGRES_PTYPE_UINT16;
		else if (dv[i].value->type == pt_uint32->type)
			dv[i].native_type = POSTGRES_PTYPE_UINT32;
		else if (dv[i].value->type == pt_uint64->type)
			dv[i].native_type = POSTGRES_PTYPE_UINT64;
		else if (dv[i].value->type == pt_string->type)
			dv[i].native_type = POSTGRES_PTYPE_STRING;
		else if (dv[i].value->type == pt_timestamp->type)
			dv[i].native_type = POSTGRES_PTYPE_TIMESTAMP;
		else
			dv[i].native_type = POSTGRES_PTYPE_OTHER;

		size = strlen(priv->read_query_start) + strlen(dv[i].name) + strlen(", ");
		priv->read_query_start = realloc(priv->read_query_start, size + 1);
		strcat(priv->read_query_start, dv[i].name);
		if (dv[i + 1].name)
			strcat(priv->read_query_start, ", ");

	}

	size = strlen(priv->read_query_start) + strlen(" FROM ") + strlen(ds->name) + 1;
	priv->read_query_start = realloc(priv->read_query_start, size);
	strcat(priv->read_query_start, " FROM " );
	strcat(priv->read_query_start, ds->name);


	new_size = 1;
	priv->read_query = malloc(new_size);
	priv->read_query_buff = malloc(2);
	priv->read_query_buff_size = 1;

	do {
		size = new_size;
		new_size = snprintf(priv->read_query, size, "FETCH ALL IN %s_cur", ds->name);
		new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
		priv->read_query = realloc(priv->read_query, new_size + 1);
	} while (new_size > size);

	pom_log(POM_LOG_TSHOOT "READ START QUERY : %s", priv->read_query_start);
	pom_log(POM_LOG_TSHOOT "READ QUERY : %s", priv->read_query);

	new_size = 1;
	priv->read_query_end = malloc(new_size);
	do {
		size = new_size;
		new_size = snprintf(priv->read_query_end, size, "CLOSE %s_cur", ds->name);
		new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
		priv->read_query_end = realloc(priv->read_query_end, new_size + 1);
	} while (new_size > size);
	pom_log(POM_LOG_TSHOOT "READ END QUERY : %s", priv->read_query_end);

	new_size = 1;
	priv->write_query = malloc(new_size);
	do {
		size = new_size;
		new_size = snprintf(priv->write_query, size, "INSERT INTO %s ( " POSTGRES_PKID_NAME ", ", ds->name);
		new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
		priv->write_query = realloc(priv->write_query, new_size + 1);
	} while (new_size > size);

	for (i = 0; dv[i].name; i++) {
		size = strlen(priv->write_query) + strlen(dv[i].name) + strlen(", ") + 1;
		priv->write_query = realloc(priv->write_query, size);
		strcat(priv->write_query, dv[i].name);
		if (dv[i + 1].name)
			strcat(priv->write_query, ", ");

	}

	size += strlen(") VALUES ( nextval('") + strlen(ds->name) + strlen("_seq'), ") + 1;
	priv->write_query = realloc(priv->write_query, size);
	strcat(priv->write_query, ") VALUES ( nextval('");
	strcat(priv->write_query, ds->name);
	strcat(priv->write_query, "_seq'), ");

	for (i = 0; dv[i].name; i++) {
		char buff[64];
		switch (dv[i].native_type) {
			case POSTGRES_PTYPE_BOOL:
				sprintf(buff, "$%u::boolean", i + 1);
				break;
			case POSTGRES_PTYPE_UINT8:
			case POSTGRES_PTYPE_UINT16:
				sprintf(buff, "$%u::smallint", i + 1);
				break;
			case POSTGRES_PTYPE_UINT32:
				sprintf(buff, "$%u::integer", i + 1);
				break;
			case POSTGRES_PTYPE_UINT64:
				sprintf(buff, "$%u::bigint", i + 1);
				break;
			case POSTGRES_PTYPE_TIMESTAMP:
				sprintf(buff, "$%u::timestamp", i + 1);
				break;
			default:
				sprintf(buff, "$%u::varchar", i + 1);
				break;
		}
		size += strlen(buff) + strlen(", ");
		priv->write_query = realloc(priv->write_query, size + 1);
		strcat(priv->write_query, buff);
		if (dv[i + 1].name)
			strcat(priv->write_query, ", ");

	}

	size += strlen(");") + 1;
	priv->write_query = realloc(priv->write_query, size);
	strcat(priv->write_query, ");");

	size = strlen("SELECT currval('") + strlen(ds->name) + strlen("_seq');") + 1;
	priv->write_query_get_id = malloc(size);
	strcpy(priv->write_query_get_id, "SELECT currval('");
	strcat(priv->write_query_get_id, ds->name);
	strcat(priv->write_query_get_id, "_seq');");

	priv->num_fields = i;

	priv->write_data_buff = malloc(sizeof(union datastore_postgres_data) * priv->num_fields);
	priv->write_query_param_val = malloc(sizeof(char *) * priv->num_fields);
	priv->write_query_param_len = malloc(sizeof(int *) * priv->num_fields);

	priv->write_query_param_format = malloc(sizeof(int) * priv->num_fields);

	for (i = 0; i < priv->num_fields; i++)
		priv->write_query_param_format[i] = 1; // We use binary format only


	pom_log(POM_LOG_TSHOOT "WRITE QUERY : %s", priv->write_query);
	pom_log(POM_LOG_TSHOOT "WRITE QUERY GET ID : %s", priv->write_query_get_id);
	ds->priv = priv;

	return POM_OK;
}

static int datastore_dataset_create_postgres(struct dataset *ds) {

	struct datavalue *dv = ds->query_data;

	unsigned int len = strlen("CREATE SEQUENCE ") + strlen(ds->name) + strlen("_seq; ") + \
		strlen("CREATE TABLE ") + strlen(ds->name) + strlen(" ( " POSTGRES_PKID_NAME " bigint NOT NULL PRIMARY KEY, ") + strlen(" );");

	char *query = malloc(len + 1);
	memset(query, 0, len + 1);

	strcat(query, "CREATE SEQUENCE ");
	strcat(query, ds->name);
	strcat(query, "_seq; ");

	strcat(query, "CREATE TABLE ");
	strcat(query, ds->name);
	strcat(query, " ( " POSTGRES_PKID_NAME " bigint NOT NULL PRIMARY KEY, ");

	int i;
	for (i = 0; dv[i].name; i++) {
	
		char *type = " varchar";
		switch (dv[i].native_type) {
			case POSTGRES_PTYPE_BOOL:
				type = " boolean";
				break;
			case POSTGRES_PTYPE_UINT8:
			case POSTGRES_PTYPE_UINT16:
				type = " smallint";
				break;
			case POSTGRES_PTYPE_UINT32:
				type = " integer";
				break;
			case POSTGRES_PTYPE_UINT64:
				type = " bigint";
				break;
			case POSTGRES_PTYPE_TIMESTAMP:
				type = " timestamp";
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

	strcat(query, " );");
	
	pom_log(POM_LOG_TSHOOT "CREATE QUERY : %s", query);

	int res = postgres_exec(ds, query);
	free(query);

	struct datastore_priv_postgres *priv = ds->dstore->priv;
	if (res == POM_ERR && priv->connection) {
		pom_log(POM_LOG_ERR "Failed to create dataset \"%s\" in datastore %s : %s", ds->name, ds->dstore->name, PQerrorMessage(priv->connection));
	}

	return res;
}

static int datastore_dataset_read_postgres(struct dataset *ds) {

	struct dataset_priv_postgres *priv = ds->priv;
	struct datastore_priv_postgres *dpriv = ds->dstore->priv;

	if (ds->state != DATASET_STATE_MORE) {
		if (postgres_exec(ds, "BEGIN;") == POM_ERR) {
			if (dpriv->connection)
				pom_log(POM_LOG_ERR "Failed to begin read transaction to dataset %s : %s", ds->name, PQerrorMessage(dpriv->connection));
			return POM_ERR;
		}

		char *read_query = priv->read_query_start;
		struct datavalue_condition *qc = ds->query_cond;
		if (qc) {
			struct datavalue *dv = ds->query_data;
			int size, new_size = priv->read_query_buff_size;

			read_query = priv->read_query_buff;

			char *string_val = NULL;
			if (dv[qc->field_id].native_type == POSTGRES_PTYPE_STRING) {
				size_t len = strlen(PTYPE_STRING_GETVAL(qc->value));
				string_val = malloc((len * 2) + 1);
				PQescapeString(string_val, PTYPE_STRING_GETVAL(qc->value), len);
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
					case POSTGRES_PTYPE_BOOL:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query_start, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
						break;
					case POSTGRES_PTYPE_UINT8:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query_start, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
						break;
					case POSTGRES_PTYPE_UINT16:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query_start, dv[qc->field_id].name, op, PTYPE_UINT16_GETVAL(qc->value));
						break;
					case POSTGRES_PTYPE_UINT32:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query_start, dv[qc->field_id].name, op, PTYPE_UINT32_GETVAL(qc->value));
						break;
					case POSTGRES_PTYPE_UINT64:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %llu", priv->read_query_start, dv[qc->field_id].name, op, (unsigned long long) PTYPE_UINT64_GETVAL(qc->value));
						break;
					case POSTGRES_PTYPE_STRING:
						new_size = snprintf(read_query, size, "%s WHERE %s %s '%s'", priv->read_query_start, dv[qc->field_id].name, op, string_val);
						break;
					default:
						pom_log(POM_LOG_ERR "Unsupported ptype in query condition");
						priv->read_query_buff = read_query;
						priv->read_query_buff_size = size;
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
			new_size = strlen(" ORDER BY ") + strlen(dv[qro->field_id].name) + 1;
			if (qro->direction)
				new_size += strlen(" DESC");

			if (read_query == priv->read_query_start) {
				read_query = priv->read_query_buff;
				new_size += strlen(priv->read_query_start);
				if (priv->read_query_buff_size < new_size) {
					read_query = realloc(read_query, new_size + 1);
					priv->read_query_buff_size = new_size;
				}
				strcpy(read_query, priv->read_query_start);

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

		PGresult *res = PQexec(dpriv->connection, read_query);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			pom_log(POM_LOG_DEBUG "Unable to execute the READ SQL query : %s", PQresultErrorMessage(res));
			ds->state = postgres_get_ds_state_error(ds, res);
			PQclear(res);
			res = PQexec(dpriv->connection, "ROLLBACK");
			PQclear(res);
			ds->state = DATASET_STATE_ERR;
			return POM_ERR;
		}
		PQclear(res);

		priv->read_res = PQexec(dpriv->connection, priv->read_query);
		if (PQresultStatus(priv->read_res) != PGRES_TUPLES_OK) {
			pom_log(POM_LOG_DEBUG "Unable to execute the READ SQL query : %s", PQresultErrorMessage(priv->read_res));
			ds->state = postgres_get_ds_state_error(ds, priv->read_res);
			PQclear(priv->read_res);
			priv->read_res = NULL;
			res = PQexec(dpriv->connection, "ROLLBACK");
			PQclear(res);
			ds->state = DATASET_STATE_ERR;
			return POM_ERR;
		}
		priv->read_query_tot = PQntuples(priv->read_res);
		priv->read_query_cur = 0;

	}

	if (priv->read_query_cur >= priv->read_query_tot) {
		ds->state = DATASET_STATE_DONE;
		PQclear(priv->read_res);

		PGresult *res = PQexec(dpriv->connection, priv->read_query_end);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			pom_log(POM_LOG_DEBUG "Error while ending the transaction : %s", PQresultErrorMessage(res));
			ds->state = postgres_get_ds_state_error(ds, res);
			PQclear(res);
			return POM_ERR;
		}
		PQclear(res);
		res = PQexec(dpriv->connection, "COMMIT");
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			pom_log(POM_LOG_DEBUG "Error while commiting the transaction : %s", PQresultErrorMessage(res));
			ds->state = postgres_get_ds_state_error(ds, res);
			PQclear(res);
			return POM_ERR;
		}
		PQclear(res);
		return POM_OK;
	}


	ds->state = DATASET_STATE_MORE;

	// First read the id
	uint64_t *ptr =  (uint64_t*) PQgetvalue(priv->read_res, priv->read_query_cur, 0);
	ds->data_id = ntohll(*ptr);

	tzset(); // Init timezone and daylight variable

	struct datavalue *dv = ds->query_data;
	int i;
	for (i = 0; dv[i].name; i++) {
		switch (dv[i].native_type) {
			case POSTGRES_PTYPE_BOOL: {
				uint8_t *res = (uint8_t*) PQgetvalue(priv->read_res, priv->read_query_cur, i + 1);
				PTYPE_BOOL_SETVAL(dv[i].value, *res);
				break;
			}
			case POSTGRES_PTYPE_UINT8: {
				uint8_t *res = (uint8_t*) PQgetvalue(priv->read_res, priv->read_query_cur, i + 1);
				PTYPE_UINT8_SETVAL(dv[i].value, *res);
				break;
			}
			case POSTGRES_PTYPE_UINT16: {
				uint16_t *res = (uint16_t*) PQgetvalue(priv->read_res, priv->read_query_cur, i + 1);
				PTYPE_UINT16_SETVAL(dv[i].value, ntohs(*res));
				break;
			}
			case POSTGRES_PTYPE_UINT32: {
				uint32_t *res = (uint32_t*) PQgetvalue(priv->read_res, priv->read_query_cur, i + 1);
				PTYPE_UINT32_SETVAL(dv[i].value, ntohl(*res));
				break;
			}
			case POSTGRES_PTYPE_UINT64: {
				uint64_t *res = (uint64_t*) PQgetvalue(priv->read_res, priv->read_query_cur, i + 1);
				PTYPE_UINT64_SETVAL(dv[i].value, ntohll(*res));
				break;
			}
			case POSTGRES_PTYPE_TIMESTAMP: {
				time_t t = 0;
				if (dpriv->integer_datetimes) {
					int64_t *my_time = (int64_t*) PQgetvalue(priv->read_res, priv->read_query_cur, i + 1);
					t = (ntohll(*my_time) / 1000000L) + ((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY);
				} else {
					// nasty trick to swap the double value
					uint64_t *my_time = (uint64_t*) PQgetvalue(priv->read_res, priv->read_query_cur, i + 1);
					uint64_t tmp = ntohll(*my_time);
					double *swp_time = (double*)&tmp;

					t = *swp_time + ((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY);
				}
				// Adjust for timezone and daylight
				// Assume that stored values are localtime
				t += timezone;
				if (daylight)
					t -= 3600;

				PTYPE_TIMESTAMP_SETVAL(dv[i].value, t);
				break;
			}
			default: {
				char *res = PQgetvalue(priv->read_res, priv->read_query_cur, i + 1);
				if (ptype_parse_val(dv[i].value, res) != POM_OK) {
					ds->state = DATASET_STATE_ERR;
					PQclear(priv->read_res);
					priv->read_res = NULL;
					return POM_ERR;
				}
				break;
			}
		}
	}
	
	priv->read_query_cur++;

	return POM_OK;
}

static int datastore_dataset_write_postgres(struct dataset *ds) {


	struct datastore_priv_postgres *dpriv = ds->dstore->priv;
	struct dataset_priv_postgres *priv = ds->priv;

	if (postgres_exec(ds, "BEGIN;") == POM_ERR) {
		if (dpriv->connection)
			pom_log(POM_LOG_ERR "Failed to begin write transaction to dataset %s : %s", ds->name, PQerrorMessage(dpriv->connection));
		return POM_ERR;
	}

	tzset(); // Init timezone and daylight variable

	struct datavalue *dv = ds->query_data;
	int i;
	for (i = 0; dv[i].name; i++) {
		switch (dv[i].native_type) {
			case POSTGRES_PTYPE_BOOL: {
				priv->write_data_buff[i].uint8 = PTYPE_BOOL_GETVAL(dv[i].value);
				priv->write_query_param_val[i] = (char*) &priv->write_data_buff[i].uint8;
				priv->write_query_param_len[i] = sizeof(uint8_t);
				break;
			}
			case POSTGRES_PTYPE_UINT8: {
				priv->write_data_buff[i].uint8 = PTYPE_UINT8_GETVAL(dv[i].value);
				priv->write_query_param_val[i] = (char*) &priv->write_data_buff[i].uint8;
				priv->write_query_param_len[i] = sizeof(uint8_t);
				break;
			}
			case POSTGRES_PTYPE_UINT16: {
				priv->write_data_buff[i].uint16 = htons(PTYPE_UINT16_GETVAL(dv[i].value));
				priv->write_query_param_val[i] = (char*) &priv->write_data_buff[i].uint16;
				priv->write_query_param_len[i] = sizeof(uint16_t);
				break;
			}
			case POSTGRES_PTYPE_UINT32: {
				priv->write_data_buff[i].uint32 = htonl(PTYPE_UINT32_GETVAL(dv[i].value));
				priv->write_query_param_val[i] = (char*) &priv->write_data_buff[i].uint32;
				priv->write_query_param_len[i] = sizeof(uint32_t);
				break;
			}
			case POSTGRES_PTYPE_UINT64: {
				priv->write_data_buff[i].uint64 = htonll(PTYPE_UINT64_GETVAL(dv[i].value));
				priv->write_query_param_val[i] = (char*) &priv->write_data_buff[i].uint64;
				priv->write_query_param_len[i] = sizeof(uint64_t);
				break;
			}
			case POSTGRES_PTYPE_TIMESTAMP: {
				time_t ts = PTYPE_TIMESTAMP_GETVAL(dv[i].value);
				// Adjust for timezone and daylight
				// Store values as localtime
				ts -= timezone;
				if (daylight)
					ts += 3600;
	
				if (dpriv->integer_datetimes) {
					int64_t my_time = ts - ((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY);
					my_time *= 1000000;
					priv->write_data_buff[i].int64 = (int64_t) htonll(my_time);
					priv->write_query_param_val[i] = (char*) &priv->write_data_buff[i].int64;
					priv->write_query_param_len[i] = sizeof(int64_t);
				} else {
					// Nasty trick to swap the double value
					double my_time = ts - ((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY);
					uint64_t *tmp = (uint64_t*)&my_time;
					double *swp_time = (double*)tmp;
					*tmp = htonll(*tmp);
					priv->write_data_buff[i].dfloat = *swp_time;
					priv->write_query_param_val[i] = (char*) &priv->write_data_buff[i].dfloat;
					priv->write_query_param_len[i] = sizeof(double);
				}
				break;

			}
			case POSTGRES_PTYPE_STRING: {
				char *value = PTYPE_STRING_GETVAL(dv[i].value);
				priv->write_query_param_val[i] = value;
				if (value) 
					priv->write_query_param_len[i] = strlen(priv->write_query_param_val[i]);
				else 
					priv->write_query_param_len[i] = 0;
				break;
			}	
			default: {
				priv->write_query_param_val[i] = ptype_print_val_alloc(dv[i].value);
				break;
			}
		}
	}
	


	PGresult *res = PQexecParams(dpriv->connection, priv->write_query, priv->num_fields, NULL, (const char * const *)priv->write_query_param_val, priv->write_query_param_len, priv->write_query_param_format, 1);

	// Free allocated stuff for PTYPE_OTHER
	for (i = 0; dv[i].name; i++) {
		if (dv[i].native_type == POSTGRES_PTYPE_OTHER)
			free(priv->write_query_param_val[i]);
	}

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		pom_log(POM_LOG_ERR "Failed to write to dataset \"%s\" : %s", ds->name, PQresultErrorMessage(res));
		ds->state = postgres_get_ds_state_error(ds, res);
		PQclear(res);
		PQexec(dpriv->connection, "ROLLBACK");
		return POM_ERR;
	}
	PQclear(res);

	// Find out the last inserted pkid
	res = PQexecParams(dpriv->connection, priv->write_query_get_id, 0, NULL, NULL, NULL, NULL, 1);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		pom_log(POM_LOG_ERR "Failed to read the last inserted PKID : %s", PQresultErrorMessage(res));
		ds->state = postgres_get_ds_state_error(ds, res);
		PQclear(res);
		PQexec(dpriv->connection, "ROLLBACK");
		return POM_ERR;
	}
	uint64_t* ptr = (uint64_t*) PQgetvalue(res, 0, 0);
	ds->data_id = ntohll(*ptr);

	PQclear(res);

	// Commit
	res = PQexec(dpriv->connection, "COMMIT;");
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		pom_log(POM_LOG_ERR "Failed to commit the write to dataset \"%s\" : %s", ds->name, PQresultErrorMessage(res));
		ds->state = postgres_get_ds_state_error(ds, res);
		PQclear(res);
		return POM_ERR;
	}
	PQclear(res);

	return POM_OK;
}

static int datastore_dataset_delete_postgres(struct dataset* ds) {

	int size, new_size = 64;
	char *query = malloc(new_size + 1);
	struct datavalue_condition *qc = ds->query_cond;
	if (qc) {
		struct datavalue *dv = ds->query_data;

		char *string_val = NULL;
		if (dv[qc->field_id].native_type == POSTGRES_PTYPE_STRING) {
			size_t len = strlen(PTYPE_STRING_GETVAL(qc->value));
			string_val = malloc((len * 2) + 1);
			PQescapeString(string_val, PTYPE_STRING_GETVAL(qc->value), len);
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
				case POSTGRES_PTYPE_BOOL:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
					break;
				case POSTGRES_PTYPE_UINT8:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
					break;
				case POSTGRES_PTYPE_UINT16:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT16_GETVAL(qc->value));
					break;
				case POSTGRES_PTYPE_UINT32:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT32_GETVAL(qc->value));
					break;
				case POSTGRES_PTYPE_UINT64:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %llu", ds->name, dv[qc->field_id].name, op, (unsigned long long) PTYPE_UINT64_GETVAL(qc->value));
					break;
				case POSTGRES_PTYPE_STRING:
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

	int res = postgres_exec(ds, query);
	free(query);

	return res;
}

static int datastore_dataset_destroy_postgres(struct dataset *ds) {

	int size = 0, new_size = 64;
	char *query = malloc(new_size + 1);
	do {
		size = new_size;
		new_size = snprintf(query, size, "DROP TABLE %s; DROP SEQUENCE %s_seq;", ds->name, ds->name);
		new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
		query = realloc(query, new_size + 1);
	} while (new_size > size);

	int res = postgres_exec(ds, query);
	free(query);

	return res;
}

static int datastore_dataset_cleanup_postgres(struct dataset *ds) {

	struct dataset_priv_postgres *priv = ds->priv;
	free(priv->read_query_start);
	free(priv->read_query);
	free(priv->read_query_buff);
	free(priv->read_query_end);
	free(priv->write_query);
	free(priv->write_query_get_id);
	free(priv->write_data_buff);
	free(priv->write_query_param_val);
	free(priv->write_query_param_len);
	free(priv->write_query_param_format);
	free(priv);

	return POM_OK;

}


static int datastore_close_postgres(struct datastore *d) {

	struct datastore_priv_postgres *priv = d->priv;

	if (priv->conninfo)
		free(priv->conninfo);
	if (priv->connection) {
		PQfinish(priv->connection);
		priv->connection = NULL;
		pom_log(POM_LOG_INFO "Connection to the database closed");
	}

	return POM_OK;
}

static int datastore_cleanup_postgres(struct datastore *d) {

	struct datastore_priv_postgres *priv = d->priv;

	if (priv) {
		ptype_cleanup(priv->dbname);
		ptype_cleanup(priv->host);
		ptype_cleanup(priv->port);
		ptype_cleanup(priv->user);
		ptype_cleanup(priv->password);
		free(d->priv);
		d->priv = NULL;
	}

	return POM_OK;
}

static int datastore_unregister_postgres(struct datastore_reg *r) {

	ptype_cleanup(pt_bool);
	ptype_cleanup(pt_uint8);
	ptype_cleanup(pt_uint16);
	ptype_cleanup(pt_uint32);
	ptype_cleanup(pt_uint64);
	ptype_cleanup(pt_string);
	ptype_cleanup(pt_timestamp);

	return POM_OK;

}

static int postgres_exec(struct dataset *ds, const char *query) {

	struct datastore_priv_postgres *priv = ds->dstore->priv;

	PGresult *res = PQexec(priv->connection, query);

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		if (PQstatus(priv->connection) == CONNECTION_BAD) { // Try to reconnect
			PQclear(res);

			if (postgres_reconnect(priv) == POM_ERR) {
				ds->state = DATASET_STATE_DATASTORE_ERR;
				return POM_ERR;
			}

			// We should be reconnected now
			res = PQexec(priv->connection, query);
			if (PQresultStatus(res) == PGRES_COMMAND_OK) {
				PQclear(res);
				ds->state = DATASET_STATE_DONE;
				return POM_OK;
			}
		}

		ds->state = postgres_get_ds_state_error(ds, res);
		PQclear(res);
		return POM_ERR;

	}

	PQclear(res);
	ds->state = DATASET_STATE_DONE;
	return POM_OK;

}

static int postgres_get_ds_state_error(struct dataset *ds, PGresult *res) {

	char *errcode = PQresultErrorField(res, PG_DIAG_SQLSTATE);

	switch (*errcode) { // Select correct state depending on error class
		case '2':
		case '3':
		case '4':
			// Likely to be a dataset specific error
			return DATASET_STATE_ERR;
	}

	return DATASET_STATE_DATASTORE_ERR;

}

static int postgres_reconnect(struct datastore_priv_postgres *priv) {

	if (PQstatus(priv->connection) == CONNECTION_OK)
		return POM_OK;

	pom_log(POM_LOG_WARN "Connection to database %s on %s lost. Reconnecting", PTYPE_STRING_GETVAL(priv->dbname), PTYPE_STRING_GETVAL(priv->host));
	PQfinish(priv->connection);

	priv->connection = PQconnectdb(priv->conninfo);

	if (PQstatus(priv->connection) != CONNECTION_OK) {
		char *error = PQerrorMessage(priv->connection);
		char *br = strchr(error, '\n');
		if (br) *br = 0;
		pom_log(POM_LOG_ERR "Unable to reconnect : %s", error);
		PQfinish(priv->connection);
		priv->connection = NULL;

		return POM_ERR;
	}
	PQsetNoticeProcessor(priv->connection, postgres_notice_processor, NULL);

	return POM_OK;
}


static void postgres_notice_processor(void *arg, const char *message) {

	pom_log(POM_LOG_DEBUG "%s", message);

}

