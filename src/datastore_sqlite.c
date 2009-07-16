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

#include "datastore_sqlite.h"

#include "ptype_bool.h"
#include "ptype_uint8.h"
#include "ptype_uint16.h"
#include "ptype_uint32.h"
#include "ptype_uint64.h"

#define SQLITE_PKID_NAME	"pkid"

#define SQLITE_PTYPE_OTHER	0
#define SQLITE_PTYPE_BOOL	1
#define SQLITE_PTYPE_UINT8	2
#define SQLITE_PTYPE_UINT16	3
#define SQLITE_PTYPE_UINT32	4
#define SQLITE_PTYPE_UINT64	5
#define SQLITE_PTYPE_STRING	6

static struct ptype *pt_bool, *pt_uint8, *pt_uint16, *pt_uint32, *pt_uint64, *pt_string;

int datastore_register_sqlite(struct datastore_reg *r) {


	// Allocate ptypes to keep refcount and get their id
	pt_bool = ptype_alloc("bool", NULL);
	pt_uint8 = ptype_alloc("uint8", NULL);
	pt_uint16 = ptype_alloc("uint16", NULL);
	pt_uint32 = ptype_alloc("uint32", NULL);
	pt_uint64 = ptype_alloc("uint64", NULL);
	pt_string = ptype_alloc("string", NULL);

	if (!pt_bool || !pt_uint8 || !pt_uint16 || !pt_uint32 || !pt_uint64 || !pt_string) {
		datastore_unregister_sqlite(r);
		return POM_ERR;
	}

	r->init = datastore_init_sqlite;
	r->open = datastore_open_sqlite;
	r->dataset_alloc = datastore_dataset_alloc_sqlite;
	r->dataset_create = datastore_dataset_create_sqlite;
	r->dataset_read = datastore_dataset_read_sqlite;
	r->dataset_write = datastore_dataset_write_sqlite;
	r->dataset_delete = datastore_dataset_delete_sqlite;
	r->dataset_destroy = datastore_dataset_destroy_sqlite;
	r->dataset_cleanup = datastore_dataset_cleanup_sqlite;
	r->close = datastore_close_sqlite;
	r->cleanup = datastore_cleanup_sqlite;
	r->unregister = datastore_unregister_sqlite;

	datastore_register_param(r, "dbfile", "pom.db", "Database name");

	return POM_OK;
}


static int datastore_init_sqlite(struct datastore *d) {

	struct datastore_priv_sqlite *priv = malloc(sizeof(struct datastore_priv_sqlite));
	memset(priv, 0, sizeof(struct datastore_priv_sqlite));

	d->priv = priv;

	priv->dbfile = ptype_alloc("string", NULL);

	if (!priv->dbfile) {
		datastore_cleanup_sqlite(d);
		return POM_ERR;
	}

	datastore_register_param_value(d, "dbfile", priv->dbfile);

	return POM_OK;
}

static int datastore_open_sqlite(struct datastore *d) {

	struct datastore_priv_sqlite *priv = d->priv;

	char *dbfile = PTYPE_STRING_GETVAL(priv->dbfile);

	int res = sqlite3_open(dbfile, &priv->db);

	if (res) {
		pom_log(POM_LOG_ERR "Connection to database %s failed: %s", dbfile, sqlite3_errmsg(priv->db));
		sqlite3_close(priv->db);
		priv->db = NULL;
		return POM_ERR;
	}

	pom_log(POM_LOG_INFO "Connected on database %s", dbfile);

	return POM_OK;

}

static int datastore_dataset_alloc_sqlite(struct dataset *ds) {


	struct dataset_priv_sqlite *priv = malloc(sizeof(struct dataset_priv_sqlite));
	memset(priv, 0, sizeof(struct dataset_priv_sqlite));

	int size = strlen("SELECT " SQLITE_PKID_NAME ", ") + strlen(" FROM ") + strlen(ds->name);
	priv->read_query = malloc(size + 1);
	strcpy(priv->read_query, "SELECT " SQLITE_PKID_NAME ", ");
	int i;
	struct datavalue *dv = ds->query_data;
	for (i = 0; dv[i].name; i++) {
		
		if (dv[i].value->type == pt_bool->type)
			dv[i].native_type = SQLITE_PTYPE_BOOL;
		else if (dv[i].value->type == pt_uint8->type)
			dv[i].native_type = SQLITE_PTYPE_UINT8;
		else if (dv[i].value->type == pt_uint16->type)
			dv[i].native_type = SQLITE_PTYPE_UINT16;
		else if (dv[i].value->type == pt_uint32->type)
			dv[i].native_type = SQLITE_PTYPE_UINT32;
		else if (dv[i].value->type == pt_uint64->type)
			dv[i].native_type = SQLITE_PTYPE_UINT64;
		else if (dv[i].value->type == pt_string->type)
			dv[i].native_type = SQLITE_PTYPE_STRING;
		else
			dv[i].native_type = SQLITE_PTYPE_OTHER;

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

	ds->priv = priv;



	return POM_OK;
}

static int datastore_dataset_create_sqlite(struct dataset *ds) {


	struct datastore_priv_sqlite *priv = ds->dstore->priv;

	struct datavalue *dv = ds->query_data;

	char *query = NULL;

	unsigned int len = strlen("CREATE TABLE ") + strlen(ds->name) + strlen(" ( " SQLITE_PKID_NAME " INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ") + strlen(" )");
	int i;

	query = malloc(len + 1);
	memset(query, 0, len + 1);

	strcpy(query, "CREATE TABLE ");
	strcat(query, ds->name);
	strcat(query, " ( " SQLITE_PKID_NAME " INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ");

	for (i = 0; dv[i].name; i++) {
		
		len += strlen(dv[i].name);

		char *type = " INTEGER";
		if (dv[i].native_type == SQLITE_PTYPE_OTHER || dv[i].native_type == SQLITE_PTYPE_STRING)
			type = " STRING";
		len += strlen(type);
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

	int res = sqlite3_exec(priv->db, query, NULL, NULL, NULL);

	free(query);

	if (res != SQLITE_OK) {
		ds->state = sqlite_get_ds_state_error(res);
		pom_log(POM_LOG_ERR "Failed to create dataset \"%s\"", ds->name);
		return POM_ERR;
	}

	ds->state = DATASET_STATE_DONE;

	return POM_OK;
}

static int datastore_dataset_read_sqlite(struct dataset *ds) {

	struct dataset_priv_sqlite *priv = ds->priv;
	struct datastore_priv_sqlite *dpriv = ds->dstore->priv;


	if (ds->state != DATASET_STATE_MORE) {
		char *read_query = priv->read_query;

		struct datavalue_condition *qc = ds->query_cond;
		if (qc) {
			struct datavalue *dv = ds->query_data;
			int size, new_size = priv->read_query_buff_size;

			read_query = priv->read_query_buff;

			char *string_val = NULL;
			if (dv[qc->field_id].native_type == SQLITE_PTYPE_STRING) {
				size_t len = strlen(PTYPE_STRING_GETVAL(qc->value));
				string_val = malloc((len * 2) + 1);
				sqlite_escape_string(string_val, PTYPE_STRING_GETVAL(qc->value), len);
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
					case SQLITE_PTYPE_BOOL:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
						break;
					case SQLITE_PTYPE_UINT8:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
						break;
					case SQLITE_PTYPE_UINT16:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query, dv[qc->field_id].name, op, PTYPE_UINT16_GETVAL(qc->value));
						break;
					case SQLITE_PTYPE_UINT32:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %u", priv->read_query, dv[qc->field_id].name, op, PTYPE_UINT32_GETVAL(qc->value));
						break;
					case SQLITE_PTYPE_UINT64:
						new_size = snprintf(read_query, size, "%s WHERE %s %s %llu", priv->read_query, dv[qc->field_id].name, op, (unsigned long long) PTYPE_UINT64_GETVAL(qc->value));
						break;
					case SQLITE_PTYPE_STRING:
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

		int res = sqlite3_prepare_v2(dpriv->db, read_query, -1, &priv->read_stmt, NULL);
		if (res != SQLITE_OK) {
			ds->state = sqlite_get_ds_state_error(res);
			pom_log(POM_LOG_DEBUG "Unable to prepare the READ SQL query : %s", sqlite3_errmsg(dpriv->db));
			return POM_ERR;
		}
	}

	int res = sqlite3_step(priv->read_stmt);
	if (res == SQLITE_DONE) {
		ds->state = DATASET_STATE_DONE;
		sqlite3_finalize(priv->read_stmt);
		priv->read_stmt = NULL;
		return POM_OK;
	} else if (res != SQLITE_ROW) {
		pom_log(POM_LOG_ERR "Error while reading data from dataset %s : %s", ds->name, sqlite3_errmsg(dpriv->db));
		ds->state = sqlite_get_ds_state_error(res);
		sqlite3_finalize(priv->read_stmt);
		priv->read_stmt = NULL;
		return POM_ERR;
	}

	ds->state = DATASET_STATE_MORE;

	// First read the id
	ds->data_id = sqlite3_column_int64(priv->read_stmt, 0);

	struct datavalue *dv = ds->query_data;
	int i;
	for (i = 0; dv[i].name; i++) {
		switch (dv[i].native_type) {
			case SQLITE_PTYPE_BOOL: {
				int res = sqlite3_column_int(priv->read_stmt, i + 1);
				PTYPE_BOOL_SETVAL(dv[i].value, res);
				break;
			}
			case SQLITE_PTYPE_UINT8: {
				uint8_t res = sqlite3_column_int(priv->read_stmt, i + 1);
				PTYPE_UINT8_SETVAL(dv[i].value, res);
				break;
			}
			case SQLITE_PTYPE_UINT16: {
				uint16_t res = sqlite3_column_int(priv->read_stmt, i + 1);
				PTYPE_UINT16_SETVAL(dv[i].value, res);
				break;
			}
			case SQLITE_PTYPE_UINT32: {
				uint32_t res = sqlite3_column_int(priv->read_stmt, i + 1);
				PTYPE_UINT32_SETVAL(dv[i].value, res);
				break;
			}
			case SQLITE_PTYPE_UINT64: {
				uint64_t res = sqlite3_column_int64(priv->read_stmt, i + 1);
				PTYPE_UINT64_SETVAL(dv[i].value, res);
				break;
			}
			default: {
				const unsigned char *res = sqlite3_column_text(priv->read_stmt, i + 1);
				if (ptype_parse_val(dv[i].value, (char*) res) != POM_OK) {
					ds->state = DATASET_STATE_ERR;
					sqlite3_finalize(priv->read_stmt);
					priv->read_stmt = NULL;
					return POM_ERR;
				}
				break;
			}
		}
	}
	
	return POM_OK;
}

static int datastore_dataset_write_sqlite(struct dataset *ds) {

	struct datastore_priv_sqlite *dpriv = ds->dstore->priv;
	struct dataset_priv_sqlite *priv = ds->priv;

	int res;

	if (priv->write_stmt) {
		res = sqlite3_reset(priv->write_stmt);
		if (res != SQLITE_OK) {
			ds->state = sqlite_get_ds_state_error(res);
			pom_log(POM_LOG_ERR "Unable to reset the prepared write query : %s", sqlite3_errmsg(dpriv->db));
			return POM_ERR;
		}
	} else {
		res = sqlite3_prepare_v2(dpriv->db, priv->write_query, -1, &priv->write_stmt, NULL);
		if (res != SQLITE_OK) {
			ds->state = sqlite_get_ds_state_error(res);
			pom_log(POM_LOG_ERR "Error while while preparing the write query : %s", sqlite3_errmsg(dpriv->db));
			return POM_ERR;
		}
	}

	struct datavalue *dv = ds->query_data;
	int i;
	for (i = 0; dv[i].name; i++) {
		switch (dv[i].native_type) {
			case SQLITE_PTYPE_BOOL:
				res = sqlite3_bind_int(priv->write_stmt, i + 1, PTYPE_BOOL_GETVAL(dv[i].value));
				break;
			case SQLITE_PTYPE_UINT8:
				res = sqlite3_bind_int(priv->write_stmt, i + 1, PTYPE_UINT8_GETVAL(dv[i].value));
				break;
			case SQLITE_PTYPE_UINT16:
				res = sqlite3_bind_int(priv->write_stmt, i + 1, PTYPE_UINT16_GETVAL(dv[i].value));
				break;
			case SQLITE_PTYPE_UINT32:
				res = sqlite3_bind_int(priv->write_stmt, i + 1, PTYPE_UINT32_GETVAL(dv[i].value));
				break;
			case SQLITE_PTYPE_UINT64:
				res = sqlite3_bind_int64(priv->write_stmt, i + 1, PTYPE_UINT64_GETVAL(dv[i].value));
				break;
			case SQLITE_PTYPE_STRING:
				res = sqlite3_bind_text(priv->write_stmt, i + 1, PTYPE_STRING_GETVAL(dv[i].value), -1, SQLITE_STATIC);
				break;
			default: {
				int size, new_size = DATASTORE_SQLITE_TEMP_BUFFER_SIZE;
				char *value = NULL;
				do {
					size = new_size;
					value = realloc(value, size + 1);
					new_size = ptype_print_val(dv[i].value, value, size);
					new_size = (new_size < 1) ? new_size * 2 : new_size + 1;
				} while (new_size > size);

				res = sqlite3_bind_text(priv->write_stmt, i + 1, value, -1, SQLITE_TRANSIENT);
				break;
			}
		}
		if (res != SQLITE_OK) {
			ds->state = sqlite_get_ds_state_error(res);
			pom_log(POM_LOG_ERR "Unable to bind the value to the query : %s", sqlite3_errmsg(dpriv->db));
			return POM_ERR;
		}
		
	}

	res = sqlite3_step(priv->write_stmt);
	if (res != SQLITE_DONE) {
		ds->state = sqlite_get_ds_state_error(res);
		pom_log(POM_LOG_DEBUG "Unable to execute the write query : %s", sqlite3_errmsg(dpriv->db));
		return POM_ERR;
	}

	ds->data_id = sqlite3_last_insert_rowid(dpriv->db);

	return POM_OK;
}

static int datastore_dataset_delete_sqlite(struct dataset* ds) {

	struct datastore_priv_sqlite *priv = ds->dstore->priv;
	int size, new_size = 64;
	char *query = malloc(new_size + 1);
	struct datavalue_condition *qc = ds->query_cond;
	if (qc) {
		struct datavalue *dv = ds->query_data;

		char *string_val = NULL;
		if (dv[qc->field_id].native_type == SQLITE_PTYPE_STRING) {
			size_t len = strlen(PTYPE_STRING_GETVAL(qc->value));
			string_val = malloc((len * 2) + 1);
			sqlite_escape_string(string_val, PTYPE_STRING_GETVAL(qc->value), len);
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
				case SQLITE_PTYPE_BOOL:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
					break;
				case SQLITE_PTYPE_UINT8:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT8_GETVAL(qc->value));
					break;
				case SQLITE_PTYPE_UINT16:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT16_GETVAL(qc->value));
					break;
				case SQLITE_PTYPE_UINT32:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %u", ds->name, dv[qc->field_id].name, op, PTYPE_UINT32_GETVAL(qc->value));
					break;
				case SQLITE_PTYPE_UINT64:
					new_size = snprintf(query, size, "DELETE FROM %s WHERE %s %s %llu", ds->name, dv[qc->field_id].name, op, (unsigned long long) PTYPE_UINT64_GETVAL(qc->value));
					break;
				case SQLITE_PTYPE_STRING:
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

	int res = sqlite3_exec(priv->db, query, NULL, NULL, NULL);
	free(query);

	if (res != SQLITE_OK) {
		ds->state = sqlite_get_ds_state_error(res);
		pom_log(POM_LOG_ERR "Failed to delete entries from dataset \"%s\"", ds->name);
		return POM_ERR;
	}

	ds->state = DATASET_STATE_DONE;

	return res;
}

static int datastore_dataset_destroy_sqlite(struct dataset *ds) {

	struct datastore_priv_sqlite *priv = ds->dstore->priv;
	int size = 0, new_size = 32;
	char *query = malloc(new_size + 1);
	do {
		size = new_size;
		new_size = snprintf(query, size, "DROP TABLE %s", ds->name);
		new_size = ((new_size <= -1) ? size * 2 : new_size + 1);
		query = realloc(query, new_size + 1);
	} while (new_size > size);

	int res = sqlite3_exec(priv->db, query, NULL, NULL, NULL);
	free(query);

	if (res != SQLITE_OK) {
		ds->state = sqlite_get_ds_state_error(res);
		pom_log(POM_LOG_ERR "Failed to create destroy \"%s\"", ds->name);
		return POM_ERR;
	}

	ds->state = DATASET_STATE_DONE;

	return res;
}

static int datastore_dataset_cleanup_sqlite(struct dataset *ds) {

	struct dataset_priv_sqlite *priv = ds->priv;
	free(priv->read_query);
	free(priv->read_query_buff);
	if (priv->read_stmt)
		sqlite3_finalize(priv->read_stmt);

	free(priv->write_query);
	if (priv->write_stmt)
		sqlite3_finalize(priv->write_stmt);
	free(priv);

	return POM_OK;

}

static int datastore_close_sqlite(struct datastore *d) {

	struct datastore_priv_sqlite *priv = d->priv;
	if (priv->db) {
		sqlite3_close(priv->db);
		priv->db = NULL;
		pom_log(POM_LOG_INFO "Connection to the database closed");
	}

	return POM_OK;
}

static int datastore_cleanup_sqlite(struct datastore *d) {

	struct datastore_priv_sqlite *priv = d->priv;

	if (priv) {
		ptype_cleanup(priv->dbfile);
		free(d->priv);
		d->priv = NULL;
	}


	return POM_OK;
}

static int datastore_unregister_sqlite(struct datastore_reg *r) {
	ptype_cleanup(pt_bool);
	ptype_cleanup(pt_uint8);
	ptype_cleanup(pt_uint16);
	ptype_cleanup(pt_uint32);
	ptype_cleanup(pt_uint64);
	ptype_cleanup(pt_string);

	return POM_OK;
}

static int sqlite_get_ds_state_error(int res) {

	switch (res) {
		case SQLITE_ERROR:
		case SQLITE_ABORT:
		case SQLITE_MISMATCH:
			return DATASET_STATE_ERR;
	}
	
	return DATASET_STATE_DATASTORE_ERR;
}

static size_t sqlite_escape_string(char *to, char *from, size_t len) {

	size_t out_len = 0, i;

	for (i = 0; i < len; i++) {

		switch (from[i]) {
			case '\'':
			case '\\':
				to[out_len] = '\\';
				to[out_len + 1] = from[i];
				out_len += 2;
				break;

			default:
				to[out_len] = from[i];
				out_len++;
				break;

		}
	}
	to[out_len] = 0;
	out_len++;

	return out_len;
}
