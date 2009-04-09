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

#include <byteswap.h>

#include "ptype_bool.h"
#include "ptype_uint8.h"
#include "ptype_uint16.h"
#include "ptype_uint32.h"
#include "ptype_uint64.h"

#define POSTGRES_PKID_NAME	"pkid"

#define POSTGRES_PTYPE_OTHER	0
#define POSTGRES_PTYPE_BOOL	1
#define POSTGRES_PTYPE_UINT8	2
#define POSTGRES_PTYPE_UINT16	3
#define POSTGRES_PTYPE_UINT32	4
#define POSTGRES_PTYPE_UINT64	5
#define POSTGRES_PTYPE_STRING	6

static struct ptype *pt_bool, *pt_uint8, *pt_uint16, *pt_uint32, *pt_uint64, *pt_string;

int datastore_register_postgres(struct datastore_reg *r) {

	// Allocate ptypes to keep refcount and get their id
	pt_bool = ptype_alloc("bool", NULL);
	pt_uint8 = ptype_alloc("uint8", NULL);
	pt_uint16 = ptype_alloc("uint16", NULL);
	pt_uint32 = ptype_alloc("uint32", NULL);
	pt_uint64 = ptype_alloc("uint64", NULL);
	pt_string = ptype_alloc("string", NULL);
	
	if (!pt_bool || !pt_uint8 || !pt_uint16 || !pt_uint32 || !pt_uint64 || !pt_string) {
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
	priv->port = ptype_alloc("uint16", NULL);
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

	char conninfo[2048];
	memset(conninfo, 0, sizeof(conninfo));
	char *dbname = PTYPE_STRING_GETVAL(priv->dbname);
	snprintf(conninfo, sizeof(conninfo) - 1, "dbname=%s", dbname);

	char *host = PTYPE_STRING_GETVAL(priv->host);
	if (*host) {
		snprintf(conninfo + strlen(conninfo), sizeof(conninfo) - strlen(conninfo) - 1, " host=%s", host);
	} else if (*host == '/') {
		strncat(conninfo + strlen(conninfo), " port=", sizeof(conninfo) - strlen(conninfo) - 1);
		ptype_print_val(priv->port, conninfo + strlen(conninfo), sizeof(conninfo) - strlen(conninfo) - 1);
	}

	char *user = PTYPE_STRING_GETVAL(priv->user);
	if (*user) 
		snprintf(conninfo + strlen(conninfo), sizeof(conninfo) - strlen(conninfo) - 1, " user=%s", user);

	char *password = PTYPE_STRING_GETVAL(priv->password);
	if (*password) 
		snprintf(conninfo + strlen(conninfo), sizeof(conninfo) - strlen(conninfo) - 1, " password=%s", password);

	priv->connection = PQconnectdb(conninfo);

	if (PQstatus(priv->connection) != CONNECTION_OK) {
		char *error = PQerrorMessage(priv->connection);
		char *br = strchr(error, '\n');
		if (br) *br = 0;
		pom_log(POM_LOG_ERR "Connection to database failed: %s", error);
		PQfinish(priv->connection);
		priv->connection = NULL;
		return POM_ERR;
	}

	pom_log(POM_LOG_INFO "Connected on database %s at %s", dbname, host);

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
	priv->write_query_param_val = malloc(sizeof(int) * priv->num_fields);
	priv->write_query_param_len = malloc(sizeof(int) * priv->num_fields);

	priv->write_query_param_format = malloc(sizeof(int) * priv->num_fields);

	for (i = 0; i < priv->num_fields; i++)
		priv->write_query_param_format[i] = 1; // We use binary format only


	pom_log(POM_LOG_TSHOOT "WRITE QUERY : %s", priv->write_query);
	pom_log(POM_LOG_TSHOOT "WRITE QUERY GET ID : %s", priv->write_query_get_id);
	ds->priv = priv;

	return POM_OK;
}

static int datastore_dataset_create_postgres(struct dataset *ds) {


	struct datastore_priv_postgres *priv = ds->dstore->priv;

	struct datavalue *dv = ds->query_data;

	char query[2048];
	memset(query, 0, sizeof(query));

	strcat(query, "CREATE SEQUENCE ");
	strcat(query, ds->name);
	strcat(query, "_seq; ");

	strcat(query, "CREATE TABLE ");
	strcat(query, ds->name);
	strcat(query, " ( " POSTGRES_PKID_NAME " bigint NOT NULL PRIMARY KEY, ");
	int i;
	for (i = 0; dv[i].name; i++) {
		
		strcat(query, dv[i].name);
		switch (dv[i].native_type) {
			case POSTGRES_PTYPE_BOOL:
				strcat(query, " boolean");
				break;
			case POSTGRES_PTYPE_UINT8:
			case POSTGRES_PTYPE_UINT16:
				strcat(query, " smallint");
				break;
			case POSTGRES_PTYPE_UINT32:
				strcat(query, " integer");
				break;
			case POSTGRES_PTYPE_UINT64:
				strcat(query, " bigint");
				break;
			default:
				strcat(query, " varchar");
				break;
		}
		if (dv[i + 1].name)
			strcat(query, ", ");

	}

	strcat(query, " );");
	
	pom_log(POM_LOG_TSHOOT "CREATE QUERY : %s", query);

	PGresult *res = PQexec(priv->connection, query);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		pom_log(POM_LOG_ERR "Failed to create dataset \"%s\" in datastore %s : %s", ds->name, ds->dstore->name, PQerrorMessage(priv->connection));
		PQclear(res);
		return POM_ERR;
	}

	PQclear(res);

	return POM_OK;
}

static int datastore_dataset_read_postgres(struct dataset *ds) {

	struct dataset_priv_postgres *priv = ds->priv;
	struct datastore_priv_postgres *dpriv = ds->dstore->priv;

	if (ds->state != DATASET_STATE_MORE) {
		 PGresult *res = PQexec(dpriv->connection, "BEGIN");
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			pom_log(POM_LOG_DEBUG "Unable to read to dataset %s query : %s", ds->name, PQresultErrorMessage(res));
			PQclear(res);
			ds->state = DATASET_STATE_ERR;
			return POM_ERR;
		}
		PQclear(res);

		char *read_query = priv->read_query_start;
		struct datavalue_read_condition *qrc = ds->query_read_cond;
		if (qrc) {
			struct datavalue *dv = ds->query_data;
			int size, new_size = priv->read_query_buff_size;

			read_query = priv->read_query_buff;
			while (1) {
				size = new_size;
				char *op = NULL;
				switch (qrc->op) {
					case PTYPE_OP_EQ:
						op = "=";
						break;
					default:
						op = ptype_get_op_sign(qrc->op);
						break;

				}
				switch (dv[qrc->field_id].native_type) {
					case POSTGRES_PTYPE_BOOL:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query_start, dv[qrc->field_id].name, op, PTYPE_UINT8_GETVAL(qrc->value));
						break;
					case POSTGRES_PTYPE_UINT8:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query_start, dv[qrc->field_id].name, op, PTYPE_UINT8_GETVAL(qrc->value));
						break;
					case POSTGRES_PTYPE_UINT16:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query_start, dv[qrc->field_id].name, op, PTYPE_UINT16_GETVAL(qrc->value));
						break;
					case POSTGRES_PTYPE_UINT32:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query_start, dv[qrc->field_id].name, op, PTYPE_UINT32_GETVAL(qrc->value));
						break;
					case POSTGRES_PTYPE_UINT64:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %llu", priv->read_query_start, dv[qrc->field_id].name, op, (unsigned long long) PTYPE_UINT64_GETVAL(qrc->value));
						break;
					case POSTGRES_PTYPE_STRING:
						new_size = snprintf(read_query, size, "%s WHERE %s %s '%s'", priv->read_query_start, dv[qrc->field_id].name, op, PTYPE_STRING_GETVAL(qrc->value));
						break;
					default:
						pom_log(POM_LOG_ERR "Unsupported ptype in read condition");
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

		res = PQexec(dpriv->connection, read_query);
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			pom_log(POM_LOG_DEBUG "Unable to execute the READ SQL query : %s", PQresultErrorMessage(res));
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
			PQclear(res);
			return POM_ERR;
		}
		PQclear(res);
		res = PQexec(dpriv->connection, "COMMIT");
		if (PQresultStatus(res) != PGRES_COMMAND_OK) {
			pom_log(POM_LOG_DEBUG "Error while commiting the transaction : %s", PQresultErrorMessage(res));
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

	PGresult *res = PQexec(dpriv->connection, "begin;");
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		pom_log(POM_LOG_ERR "failed to begin to write to dataset \"%s\" : %s", ds->name, PQresultErrorMessage(res));
		PQclear(res);
		return POM_ERR;
	}
	PQclear(res);

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
	


	res = PQexecParams(dpriv->connection, priv->write_query, priv->num_fields, NULL, (const char * const *)priv->write_query_param_val, priv->write_query_param_len, priv->write_query_param_format, 1);

	// Free allocated stuff for PTYPE_OTHER
	for (i = 0; dv[i].name; i++) {
		if (dv[i].native_type == POSTGRES_PTYPE_OTHER)
			free(priv->write_query_param_val[i]);
	}

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		pom_log(POM_LOG_ERR "Failed to write to dataset \"%s\" : %s", ds->name, PQresultErrorMessage(res));
		PQclear(res);
		PQexec(dpriv->connection, "ROLLBACK");
		return POM_ERR;
	}
	PQclear(res);

	// Find out the last inserted pkid
	res = PQexecParams(dpriv->connection, priv->write_query_get_id, 0, NULL, NULL, NULL, NULL, 1);
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		pom_log(POM_LOG_ERR "Failed to read the last inserted PKID : %s", PQresultErrorMessage(res));
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
		PQclear(res);
		return POM_ERR;
	}
	PQclear(res);

	return POM_OK;
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

static int datastore_unregister_postgres(struct datastore_reg *re) {

	ptype_cleanup(pt_bool);
	ptype_cleanup(pt_uint8);
	ptype_cleanup(pt_uint16);
	ptype_cleanup(pt_uint32);
	ptype_cleanup(pt_uint64);
	ptype_cleanup(pt_string);

	return POM_OK;

}

