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


#include "common.h"
#include "datastore.h"
#include "ptype.h"
#include "main.h"

#include "ptype_string.h"
#include "ptype_uint64.h"
#include "ptype_uint16.h"

#include <pthread.h>

const char *datasetdbdescr[][2] = {
	{ "name", "string" }, // name of the dataset
	{ "type", "string" }, // type of the dataset
	{ "description", "string" }, // description of the dataset
	{ NULL, NULL },

};

const char *datasetfieldsdescr[][2] = {
	{ "dataset_id", "uint64" }, // id of the corresponding dataset
	{ "name", "string" }, // name of the field
	{ "type", "string" }, // type of the field
	{ "field_id", "uint16" }, // Id of the field
	{ NULL, NULL},

};

struct datastore_reg *datastores[MAX_DATASTORE];

static pthread_rwlock_t datastore_global_lock = PTHREAD_RWLOCK_INITIALIZER;

/**
 * @ingroup datastore_core
 * @param datastore_name Name of the datastore to register
 * @return The id of the datastore or POM_ERR on error.
 */
int datastore_register(const char *datastore_name) {

	int i;

	for (i = 0; i < MAX_DATASTORE; i++) {
		if (datastores[i] != NULL) {
			if (datastores[i]->name && strcmp(datastores[i]->name, datastore_name) == 0) {
				return i;
			}
		} else {
			int (*register_my_datastore) (struct datastore_reg *);

			void *handle = NULL;
			register_my_datastore = lib_get_register_func("datastore", datastore_name, &handle);
			
			if (!register_my_datastore) {
				return POM_ERR;
			}

			struct datastore_reg *my_datastore = malloc(sizeof(struct datastore_reg));
			memset(my_datastore, 0, sizeof(struct datastore_reg));

			
			datastores[i] = my_datastore;
			datastores[i]->name = malloc(strlen(datastore_name) + 1);
			strcpy(datastores[i]->name, datastore_name);

			my_datastore->type = i; // Allow the datastore to know it's number at registration time

			if ((*register_my_datastore) (my_datastore) != POM_OK) {
				pom_log(POM_LOG_ERR "Error while loading datastore %s. Could not register datastore !", datastore_name);
				free(my_datastore->name);
				free(my_datastore);
				datastores[i] = NULL;
				return POM_ERR;
			}

			datastores[i]->dl_handle = handle;

			pom_log(POM_LOG_DEBUG "Datastore %s registered", datastore_name);

			return i;

		}

	}

	return POM_ERR;

}


/**
 * @ingroup datastore_api
 * @param mode The mode to register a parameter to
 * @param name The name of the parameter
 * @param defval Default value
 * @param descr Description
 * @return POM_OK on success, POM_ERR on failure.
 */
int datastore_register_param(struct datastore_reg *r, char *name, char *defval, char *descr) {

	struct datastore_param_reg *param = malloc(sizeof(struct datastore_param_reg));
	memset(param, 0, sizeof(struct datastore_param_reg));

	param->name = malloc(strlen(name) + 1);
	strcpy(param->name, name);
	param->defval = malloc(strlen(defval) + 1);
	strcpy(param->defval, defval);
	param->descr = malloc(strlen(descr) + 1);
	strcpy(param->descr, descr);

	if (!r->params) {
		r->params = param;
	} else {
		struct datastore_param_reg *tmp = r->params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = param;
	}

	return POM_OK;
}

/**
 * @ingroup datastore_api
 * @param t The datastore which is registering the value
 * @param mode The mode to which the parameter of the value belongs
 * @param name Name of the parameter to register its value
 * @param value The actual value
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int datastore_register_param_value(struct datastore *d, const char *name, struct ptype *value) {

	if (!d || !value || !datastores[d->type])
		return POM_ERR;

	struct datastore_param_reg *p = datastores[d->type]->params;
	while (p) {
		if (!strcmp(p->name, name))
			break;
		p = p->next;
	}
	if (!p)
		return POM_ERR;

	if (ptype_parse_val(value, p->defval) != POM_OK)
		return POM_ERR;

	struct datastore_param *dp = malloc(sizeof(struct datastore_param));
	memset(dp, 0, sizeof(struct datastore_param));

	dp->type = p;
	dp->value = value;


	struct datastore_param *tmp = d->params;

	if (!tmp) {
		d->params = dp;
	} else {
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = dp;

	}

	return POM_OK;


}

/**
 * @ingroup datastore_core
 * @param datastore_type Type of the datastore
 * @return The name of the datastore or NULL on error.
 */
char *datastore_get_name(int datastore_type) {

	if (datastores[datastore_type])
		return datastores[datastore_type]->name;
	
	return NULL;

}


/**
 * @ingroup datastore_core
 * @param datastore_name Name of the datastore
 * @return The id of the datastore or POM_ERR on error.
 */
int datastore_get_type(const char *datastore_name) {

	int i;
	for (i = 0; i < MAX_DATASTORE; i++) {
		if (datastores[i] && strcmp(datastores[i]->name, datastore_name) == 0)
			return i;
	}

	return POM_ERR;
}

/**
 * @ingroup datastore_core
 * @param t Target to get the value from
 * @param param Name of the parameter to get the value from
 * @return The value of the parameter or NULL on error.
 */
struct ptype *datastore_get_param_value(struct datastore *d, const char *param) {

	if (!d)
		return NULL;

	struct datastore_param *p = d->params;
	while (p) {
		if (!(strcmp(p->type->name, param)))
			break;

		p = p->next;
	}
	
	if (!p) 
		return NULL;

	return p->value;

}

/**
 * @ingroup datastore_core
 * @param datastore_type Type of the datastore to create a new instance
 * @return The new instance of the datastore or NULL on failure.
 */
struct datastore *datastore_alloc(int datastore_type) {

	if (!datastores[datastore_type]) {
		pom_log(POM_LOG_ERR "Datastore type %u is not registered", datastore_type);
		return NULL;
	}
	struct datastore *d = malloc(sizeof(struct datastore));
	memset(d, 0, sizeof(struct datastore));

	d->type = datastore_type;
	
	if (pthread_rwlock_init(&d->lock, NULL)) {
		free(d);
		return NULL;
	}


	if (datastores[datastore_type]->init)
		if ((*datastores[datastore_type]->init) (d) != POM_OK) {
			free(d);
			return NULL;
		}

	d->uid = get_uid();

	datastores[datastore_type]->refcount++;
		
	return d;
}

/**
 * @ingroup datastore_core
 * This function will grab a write lock on the datastore instance.
 * @param d Datastore to open
 * @return POM_OK on success, POM_ERR on failure.
 */
int datastore_open(struct datastore *d) {

	if (!d)
		return POM_ERR;

	if (d->started)
		return POM_ERR;

	if (datastores[d->type] && datastores[d->type]->open) {
		if ((*datastores[d->type]->open) (d) != POM_OK) {
			return POM_ERR;
		}
	}


	// Allocate the datasetdb
	struct dataset *dsdb = malloc(sizeof(struct dataset));
	struct dataset *dsfields = NULL;
	memset(dsdb, 0, sizeof(struct dataset));

	dsdb->name = malloc(strlen(DATASTORE_DATASET_TABLE_NAME) + 1);
	strcpy(dsdb->name, DATASTORE_DATASET_TABLE_NAME);
	
	dsdb->type = malloc(strlen(DATASTORE_DATASET_TYPE_NAME) + 1);
	strcpy(dsdb->type, DATASTORE_DATASET_TYPE_NAME);

	dsdb->dstore = d;


	int i;
	for (i = 0; datasetdbdescr[i][0]; i++);

	int len = sizeof(struct datavalue) * (i + 1);
	dsdb->query_data = malloc(len);
	memset(dsdb->query_data, 0, len);

	struct datavalue *qv = dsdb->query_data;
	for (i = 0; datasetdbdescr[i][0]; i++) {
		qv[i].name = malloc(strlen(datasetdbdescr[i][0]) + 1);
		strcpy(qv[i].name, datasetdbdescr[i][0]);

		qv[i].value = ptype_alloc(datasetdbdescr[i][1], NULL);
	}

	dsdb->dstore = d;
	dsdb->open = 1;

	if (datastores[d->type]->dataset_alloc) {
		if ((*datastores[d->type]->dataset_alloc) (dsdb) == POM_ERR) {
			goto err;
		}

	}

	// Allocate the dataset fields db
	
	dsfields = malloc(sizeof(struct dataset));
	memset(dsfields, 0, sizeof(struct dataset));

	dsfields->name = malloc(strlen(DATASTORE_DATASET_TABLE_NAME) + strlen("_fields") + 1);
	strcpy(dsfields->name, DATASTORE_DATASET_TABLE_NAME);
	strcat(dsfields->name, "_fields");
	
	dsfields->type = malloc(strlen(DATASTORE_DATASET_TYPE_NAME) + strlen("_fields") + 1);
	strcpy(dsfields->type, DATASTORE_DATASET_TYPE_NAME);
	strcat(dsfields->type, "_fields");


	for (i = 0; datasetfieldsdescr[i][0]; i++);

	len = sizeof(struct datavalue) * (i + 1);
	dsfields->query_data = malloc(len);
	memset(dsfields->query_data, 0, len);

	qv = dsfields->query_data;
	for (i = 0; datasetfieldsdescr[i][0]; i++) {
		qv[i].name = malloc(strlen(datasetfieldsdescr[i][0]) + 1);
		strcpy(qv[i].name, datasetfieldsdescr[i][0]);

		qv[i].value = ptype_alloc(datasetfieldsdescr[i][1], NULL);
	}

	dsfields->query_read_cond = malloc(sizeof(struct datavalue_read_condition));
	memset(dsfields->query_read_cond, 0, sizeof(struct datavalue_read_condition));
	dsfields->query_read_cond->field_id = 0;
	dsfields->query_read_cond->op = PTYPE_OP_EQ;
	dsfields->query_read_cond->value = ptype_alloc("uint64", NULL);

	dsfields->query_read_order = malloc(sizeof(struct datavalue_read_order));
	memset(dsfields->query_read_order, 0, sizeof(struct datavalue_read_order));
	dsfields->query_read_order->field_id = 3;

	dsfields->dstore = d;
	dsfields->open = 1;

	if (datastores[d->type]->dataset_alloc) {
		if ((*datastores[d->type]->dataset_alloc) (dsfields) == POM_ERR) {
			goto err;
		}

	}


	struct dataset *tmp;


	int found = 0;
	while (1) {
		int res = datastore_dataset_read(dsdb);
		if (res == POM_ERR) {
			if (found) {
				goto err;
			} else {
				break;
			}
		}
		found = 1;

		if (dsdb->state == DATASET_STATE_DONE)
			break;

		struct datavalue *dv = dsdb->query_data;

		tmp = malloc(sizeof(struct dataset));
		memset(tmp, 0, sizeof(struct dataset));
		
		char *name = PTYPE_STRING_GETVAL(dv[0].value);
		tmp->name = malloc(strlen(name) + 1);
		strcpy(tmp->name, name);

		char *type = PTYPE_STRING_GETVAL(dv[1].value);
		tmp->type = malloc(strlen(type) + 1);
		strcpy(tmp->type, type);

		char *descr = PTYPE_STRING_GETVAL(dv[2].value);
		tmp->descr = malloc(strlen(descr) + 1);
		strcpy(tmp->descr, descr);

		tmp->dataset_id = dsdb->data_id;

		tmp->dstore = d;
		
		tmp->next = d->datasets;
		d->datasets = tmp;
		
	}

	tmp = d->datasets;


	// Retrieve the fields of each dataset
	while (tmp) {

		// TODO, retrieve the structure of the dataset
		struct datavalue *dv = NULL;
		int size = 0;

		while (1) {

			PTYPE_UINT64_SETVAL(dsfields->query_read_cond->value, tmp->dataset_id);

			int res = datastore_dataset_read(dsfields);
			if (res == POM_ERR)
				goto err;

			if (dsfields->state == DATASET_STATE_DONE)
				break;

			size++;
			dv = realloc(dv, sizeof(struct datavalue) * (size + 1));
			memset(&dv[size - 1], 0, 2 * sizeof(struct datavalue));

			char *name = PTYPE_STRING_GETVAL(dsfields->query_data[1].value);
			dv[size - 1].name = malloc(strlen(name) + 1);
			strcpy(dv[size - 1].name, name);
			dv[size - 1].value = ptype_alloc(PTYPE_STRING_GETVAL(dsfields->query_data[2].value), NULL);

			if (!dv[size - 1].value) {
				pom_log(POM_LOG_ERR "Couldn't allocate ptype \"%s\"", PTYPE_STRING_GETVAL(dsfields->query_data[2].value));
				goto err;
			}
			
		}


		tmp->query_data = dv;
		tmp = tmp->next;

	}

	// the dataset table doesn't exists create it
	if (!found) {
		if ((datastore_dataset_create(dsdb) != POM_OK) || (datastore_dataset_create(dsfields) != POM_OK)) {
			pom_log("Error while creating dataset repository in datastore %s", d->name);
			goto err;
		}
	}
	
	d->datasetdb = dsdb;
	d->datasetfieldsdb = dsfields;

	d->started = 1;
	d->serial++;
	main_config->datastores_serial++;

	pom_log(POM_LOG_DEBUG "Datastore %s opened", d->name);

	return POM_OK;

err:
	while (d->datasets) {
		struct dataset *tmp = d->datasets;
		d->datasets = tmp->next;
		if (datastores[d->type]->dataset_cleanup)
			(*datastores[d->type]->dataset_cleanup) (tmp);
		struct datavalue *dv = tmp->query_data;
		if (dv) {
			int i;
			for (i = 0; dv[i].name; i++) {
				free(dv[i].name);
				ptype_cleanup(dv[i].value);
			}
			free(dv);
		}
		free(tmp->query_data);
		free(tmp->name);
		free(tmp->type);

	}

	if (dsdb) {
		if (datastores[d->type]->dataset_cleanup)
			(*datastores[d->type]->dataset_cleanup) (dsdb);
		int i;
		struct datavalue *dv = dsdb->query_data;
		if (dv) {
			for (i = 0; dv[i].name; i++) {
				free(dv[i].name);
				ptype_cleanup(dv[i].value);
			}
			free(dv);
		}
		free(dsdb->name);
		free(dsdb->type);
		free(dsdb);
	}
	if (dsfields) {
		if (datastores[d->type]->dataset_cleanup)
			(*datastores[d->type]->dataset_cleanup) (dsfields);
		int i;
		struct datavalue *dv = dsfields->query_data;
		if (dv) {
			for (i = 0; dv[i].name; i++) {
				free(dv[i].name);
				ptype_cleanup(dv[i].value);
			}
			free(dv);
		}
		if (dsfields->query_read_cond) {
			ptype_cleanup(dsfields->query_read_cond->value);
			free(dsfields->query_read_cond);
		}
		if (dsfields->query_read_order)
			free(dsfields->query_read_order);
		free(dsfields->name);
		free(dsfields->type);
		free(dsfields);
	}
	if (datastores[d->type] && datastores[d->type]->close)
		(*datastores[d->type]->close) (d);
	return POM_ERR;

}

struct dataset *datastore_dataset_open(struct datastore *d, char *name, char *type, char *descr, struct datavalue_descr *dv, int (*error_notify) (struct dataset *dset)) {

	if (!d->started) {
		pom_log(POM_LOG_ERR "Cannot open dataset %s. Datastore %s not started", name, d->name);
		return NULL;
	}


	// Check if this datastore already has the wanted dataset
	struct dataset *tmp = d->datasets;
	while (tmp) {
		if (!strcmp(tmp->name, name)) {

			break;
		}
		tmp = tmp->next;
	}
	
	// Make sure dataset we found contains all the requested fields
	if (tmp) {
		if (strcmp(tmp->type, type)) {
			pom_log(POM_LOG_ERR "Could not open dataset %s of type %s in datastore %s : Dataset type supplied differs (%s)", name, tmp->type, d->name, type);
			return NULL;
		}
		if (tmp->open) {
			pom_log(POM_LOG_ERR "Could not open dataset %s of type %s in datastore %s : Dataset already open", name, type, d->name);
			return NULL;
		}

		struct datavalue *flds = tmp->query_data;
		int i;
		for (i = 0; dv[i].name; i++) {
			if (strcmp(dv[i].name, flds[i].name) || strcmp(ptype_get_name(flds[i].value->type), dv[i].type)) {
				pom_log(POM_LOG_ERR "Could not open dataset %s of type %s in datastore %s : Dataset fields supplied differs", name, tmp->type, d->name);
				return NULL;
			}

		}

		if (flds[i].name) {
			 pom_log(POM_LOG_ERR "Could not open dataset %s of type %s in datastore %s : Dataset has more fields than supplied", name, tmp->type, d->name);
			 return NULL;
		}

		tmp->open = 1;
		tmp->dstore = d;
		tmp->error_notify = error_notify;

		if (datastores[d->type]->dataset_alloc) {
			if ((*datastores[d->type]->dataset_alloc) (tmp) == POM_ERR) {
				pom_log(POM_LOG_ERR "Unable to allocate the dataset");
				goto err;
			}
		}
	}

	// Dataset wasn't found in the datastore, let's create it
	if (!tmp) {

		pom_log("Dataset %s in datastore %s doesn't exist yet. Creating it ...", name, d->name);

		tmp = malloc(sizeof(struct dataset));
		memset(tmp, 0, sizeof(struct dataset));
		tmp->name = malloc(strlen(name) + 1);
		strcpy(tmp->name, name);

		tmp->type = malloc(strlen(type) + 1);
		strcpy(tmp->type, type);

		tmp->descr = malloc(strlen(descr) + 1);
		strcpy(tmp->descr, descr);

		tmp->dstore = d;

		// Count the number of fields
		uint16_t i;
		for (i = 0; dv[i].name; i++);

		struct datavalue *dfields = malloc(sizeof(struct datavalue) * (i + 1));
		memset(dfields, 0, sizeof(struct datavalue) * (i + 1));
		for (i = 0; dv[i].name; i++) {
			dfields[i].name = malloc(strlen(dv[i].name) + 1);
			strcpy(dfields[i].name, dv[i].name);
			dfields[i].value = ptype_alloc(dv[i].type, NULL);
			if (!dfields[i].value) {
				pom_log(POM_LOG_ERR "Unable to allocate ptype of type %s. Dataset not started", dv[i].type);
				free(dfields);
				goto err;
			}

		}

		tmp->query_data = dfields;
		tmp->dstore = d;

		if (datastores[d->type]->dataset_alloc) {
			if ((*datastores[d->type]->dataset_alloc) (tmp) == POM_ERR) {
				pom_log(POM_LOG_ERR "Unable to allocate the dataset");
				goto err;
			}
		}
	
		if (datastore_dataset_create(tmp) != POM_OK) {
			pom_log(POM_LOG_ERR "Error while creating the dataset \"%s\" in the datastore %s", tmp->name, d->name);
			goto err;
		}

		tmp->open = 1;

		struct datavalue *query = d->datasetdb->query_data;
		PTYPE_STRING_SETVAL(query[0].value, name);
		PTYPE_STRING_SETVAL(query[1].value, type);
		PTYPE_STRING_SETVAL(query[2].value, descr);
		if (datastore_dataset_write(d->datasetdb) != POM_OK) {
			pom_log(POM_LOG_ERR "Error while saving the dataset entry \"%s\" in the datastore %s", tmp->name, d->name);
			goto err;
		}

		query = d->datasetfieldsdb->query_data;
		for (i = 0; dv[i].name; i++) {
			PTYPE_UINT64_SETVAL(query[0].value, d->datasetdb->data_id);
			PTYPE_STRING_SETVAL(query[1].value, dv[i].name);
			PTYPE_STRING_SETVAL(query[2].value, dv[i].type);
			PTYPE_UINT16_SETVAL(query[3].value, i);
			if (datastore_dataset_write(d->datasetfieldsdb) != POM_OK) {
				pom_log(POM_LOG_ERR "Error while saving the dataset fields entry \"%s\" in the datastore %s", tmp->name, d->name);
				goto err;
			}
		}

		struct dataset *dsnext = d->datasets;
		if (!dsnext) {
			d->datasets = tmp;
		} else {
			while (dsnext->next)
				dsnext = dsnext->next;
			dsnext->next = tmp;
		}
	}

	pom_log(POM_LOG_DEBUG "Dataset %s opened in datastore %s", tmp->name, d->name);

	return tmp;

err:
	if (tmp && !tmp->open) { // if not open means we were allocating it
		if (tmp->priv) 
			(*datastores[d->type]->dataset_cleanup) (tmp);
		
		struct datavalue *query = tmp->query_data;
		int i;
		for (i = 0; query[i].name; i++) {
			free(query[i].name);
			ptype_cleanup(query[i].value);
		}
		free(query);
		free(tmp->name);
		free(tmp->type);
		free(tmp->descr);
		free(tmp);
	}
	return NULL;
}


int datastore_dataset_create(struct dataset *query) {

	struct datastore *d = query->dstore;

	int res = POM_OK;

	if (datastores[d->type] && datastores[d->type]->dataset_create)
		res = (*datastores[d->type]->dataset_create) (query);

	if (res != POM_OK && query->state == DATASET_STATE_DATSTORE_ERR) 
		datastore_error_notify(d);

	return res;
}

int datastore_dataset_read(struct dataset *query) {

	if (!query->open) {
		pom_log(POM_LOG_ERR "Cannot read from dataset as it's not opened yet");
		return POM_ERR;
	}

	struct datastore *d = query->dstore;

	int res = POM_ERR;

	if (datastores[d->type] && datastores[d->type]->dataset_read)
		res = (*datastores[d->type]->dataset_read) (query);

	if (res != POM_OK && query->state == DATASET_STATE_DATSTORE_ERR) 
		datastore_error_notify(d);

	return res;

}

int datastore_dataset_write(struct dataset *query) {

	struct datastore *d = query->dstore;

	if (!query->open) {
		pom_log(POM_LOG_ERR "Cannot write to dataset as it's not opened yet");
		return POM_ERR;
	}

	int res = POM_ERR;

	if (datastores[d->type] && datastores[d->type]->dataset_write)
		res = (*datastores[d->type]->dataset_write) (query);

	if (res != POM_OK && query->state == DATASET_STATE_DATSTORE_ERR) 
		datastore_error_notify(d);

	return res;

}

int datastore_dataset_close(struct dataset *ds) {

	struct datastore *d = ds->dstore;

	if (!ds->open) {
		pom_log(POM_LOG_WARN "Warning, closing already closed dataset");
		return POM_ERR;
	}

	if (datastores[d->type] && datastores[d->type]->dataset_cleanup)
		(*datastores[d->type]->dataset_cleanup) (ds);
		
		
	ds->priv = NULL;
	ds->open = 0;
	ds->error_notify = NULL;

	return POM_OK;
}

/**
 * @ingroup datastore_core
 * This function will grab a write lock on the datastore instance.
 * @param d Datastore to close
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int datastore_close(struct datastore *d) {

	if (!d)
		return POM_ERR;

	if (!d->started) 
		return POM_ERR;


	struct dataset* dset = d->datasets;


	// Check if a dataset is still in use
	while (dset) {

		if (dset->open) {
			pom_log(POM_LOG_WARN "Cannot close datastore %s. At least dataset %s is still open", d->name, dset->name);
			return POM_ERR;
		}
		dset = dset->next;
	}

	d->started = 0;

	struct datavalue *dv = NULL;
	int i;

	while (d->datasets) {
		struct dataset *tmp = d->datasets;
		d->datasets = tmp->next;
		if (tmp->open)
			datastore_dataset_close(tmp);
		dv = tmp->query_data;
		for (i = 0; dv[i].name; i++) {
			free(dv[i].name);
			ptype_cleanup(dv[i].value);
		}
		free(tmp->query_data);
		free(tmp->name);
		free(tmp->type);
		free(tmp->descr);
		free(tmp);

	}

	struct dataset *tmp = d->datasetdb;
	if (datastores[d->type]->dataset_cleanup)
		(*datastores[d->type]->dataset_cleanup) (tmp);
	dv = tmp->query_data;
	for (i = 0; dv[i].name; i++) {
		free(dv[i].name);
		ptype_cleanup(dv[i].value);
	}
	free(tmp->query_data);
	free(tmp->name);
	free(tmp->type);
	free(tmp->descr);
	free(tmp);

	tmp = d->datasetfieldsdb;
	if (datastores[d->type]->dataset_cleanup)
		(*datastores[d->type]->dataset_cleanup) (tmp);
	dv = tmp->query_data;
	for (i = 0; dv[i].name; i++) {
		free(dv[i].name);
		ptype_cleanup(dv[i].value);
	}
	if (tmp->query_read_cond) {
		ptype_cleanup(tmp->query_read_cond->value);
		free(tmp->query_read_cond);
	}
	if (tmp->query_read_order)
		free(tmp->query_read_order);
	free(tmp->query_data);
	free(tmp->name);
	free(tmp->type);
	free(tmp->descr);
	free(tmp);


	int result = POM_OK;
	if (datastores[d->type] && datastores[d->type]->close)
		result = (*datastores[d->type]->close) (d);

	d->serial++;
	main_config->datastores_serial++;

	return result;

}

/**
 * @ingroup datastore_core
 * @param datastore_type Type of the datastore
 * @return POM_OK on success or POM_ERR on failure.
 */
int datastore_refcount_inc(int datastore_type) {

	if (!datastores[datastore_type])
		return POM_ERR;
	datastores[datastore_type]->refcount++;

	return POM_OK;

}

/**
 * @ingroup datastore_core
 * @param datastore_type Type of the datastore
 * @return POM_OK on success or POM_ERR on failure.
 */
int datastore_refcount_dec(int datastore_type) {

	if (!datastores[datastore_type])
		return POM_ERR;
	
	if (datastores[datastore_type]->refcount == 0) {
		pom_log(POM_LOG_WARN "Warning, trying to decrease datastore %s reference count below 0", datastores[datastore_type]->name);
		return POM_ERR;
	}

	datastores[datastore_type]->refcount--;

	return POM_OK;

}

/**
 * @ingroup datastore_core
 * The datastore MUST be write locked when calling this function.
 * @param d Datastore to cleanup
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int datastore_cleanup(struct datastore *d) {

	if (!d || !datastores[d->type]) {
		datastore_unlock_instance(d);
		return POM_ERR;
	}

	if (datastores[d->type]->cleanup)
		(*datastores[d->type]->cleanup) (d);

	while (d->params) {
		struct datastore_param *p = d->params;
		d->params = p->next;
		free(p);
	}

	free(d->name);

	if (d->description)
		free(d->description);

	datastores[d->type]->refcount--;
	datastore_unlock_instance(d);
	pthread_rwlock_destroy(&d->lock);
	free(d);

	return POM_OK;

}


/**
 * @ingroup datastore_core
 * @param datastore_type Type of the datastore to unregister
 * @return POM_OK on success, POM_ERR on error.
 */
int datastore_unregister(unsigned int datastore_type) {

	struct datastore_reg *r = datastores[datastore_type];

	if (!r)
		return POM_ERR;

	if (r->refcount) {
		pom_log(POM_LOG_WARN "Warning, reference count not 0 for datastore %s", r->name);
		return POM_ERR;
	}

	if (r->unregister)
		(*r->unregister) (r);

	while (r->params) {
		struct datastore_param_reg *tmp = r->params;
		r->params = tmp->next;
		
		free(tmp->name);
		free(tmp->defval);
		free(tmp->descr);
		free(tmp);
	}
	
	if (dlclose(r->dl_handle))
		pom_log(POM_LOG_WARN "Error while closing library of datastore %s", r->name);

	pom_log(POM_LOG_DEBUG "Datastore %s unregistered", r->name);
	
	free(r->name);
	free(r);

	datastores[datastore_type] = NULL;

	return POM_OK;
}

/**
 * @ingroup datastore_core
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int datastore_unregister_all() {

	int i = 0;
	int result = POM_OK;

	for (; i < MAX_DATASTORE; i++)
		if (datastores[i])
			if (datastore_unregister(i) == POM_ERR)
				result = POM_ERR;

	return POM_OK;

}


/**
 * @ingroup datastore_core
 * @param write Set to 1 if helpers will be modified, 0 if not
 * @return POM_OK on success, POM_ERR on failure.
 */
int datastore_lock(int write) {

	int result = 0;
	if (write) {
		result = pthread_rwlock_wrlock(&datastore_global_lock);
	} else {
		result = pthread_rwlock_rdlock(&datastore_global_lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking the datastore lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

/**
 * @ingroup datastore_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int datastore_unlock() {

	if (pthread_rwlock_unlock(&datastore_global_lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the datastore lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

/**
 * @ingroup datastore_core
 * @param d Datastore to lock
 * @param write Get a write or read lock
 * @return POM_OK on success, POM_ERR on failure
 */
int datastore_lock_instance(struct datastore *d, int write) {

	int result = 0;

	if (write) {
		result = pthread_rwlock_wrlock(&d->lock);
	} else {
		result = pthread_rwlock_rdlock(&d->lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking a datastore instance lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

/**
 * @ingroup datastore_core
 * @param d Datastore to unlock
 * @return POM_OK on success, POM_ERR on failure
 */
int datastore_unlock_instance(struct datastore *d) {

	if (pthread_rwlock_unlock(&d->lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the datastore lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;
}


/**
 * @ingroup datastore_core
 * @param d Datastore to notify errors for
 * @return POM_OK on success, POM_ERR on failure
 */
int datastore_error_notify(struct datastore *d) {

	struct dataset *tmp = d->datasets;
	while (tmp) {
		if (tmp->open) {

			(*tmp->error_notify) (tmp);
			if (tmp->open) {
				pom_log(POM_LOG_ERR "Error, dataset %s in datastore %s wasn't closed after error notification. Aborting", d->name, tmp->name);
				abort();
			}

		}

		tmp = tmp->next;
	}

	datastore_close(d);

	return POM_OK;
}
