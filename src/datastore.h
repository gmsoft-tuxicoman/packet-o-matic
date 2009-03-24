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



#ifndef __DATASTORE_H__
#define __DATASTORE_H__

/**
 * @defgroup datastore_core Match core functions
 */
/*@{*/

/// Maximum of register datastores
#define MAX_DATASTORE 8

/// Name of the table of the datasets
#define DATASTORE_DATASET_TABLE_NAME "datasets"

/// Name of the type dataset
#define DATASTORE_DATASET_TYPE_NAME "datastore_dataset"

/// Returned by datastore_dataset_read() if there are more results
#define DATASET_STATE_ERR -1
#define DATASET_STATE_DONE 0
#define DATASET_STATE_MORE 1

/// Possible read directions
#define DATASET_READ_ORDER_ASC 0
#define DATASET_READ_ORDER_DESC 1

/// Variable that hold info about all the registered datastores
extern struct datastore_reg *datastores[MAX_DATASTORE];

/*@}*/
/** @defgroup datastore_api **/
/*@{*/

/// A dataset field description
struct datavalue_descr {
	char *name;
	char *type;
};

/// A data value
struct datavalue {
	char *name;
	unsigned int native_type;
	struct ptype *value;
};

struct datavalue_read_condition {
	uint16_t field_id; ///< Field to compare against
	int op; ///< Ptype operation
	struct ptype *value; ///< Value to compare with
};

struct datavalue_read_order {
	uint16_t field_id; ///< Field to sort
	int direction; ///< False for ascending, true for descending
};


/// A dataset
struct dataset {

	int open; ///< true if opened
	char *name;
	char *type;
	char *descr;
	int state; ///< State of the dataset
	uint64_t dataset_id; // Used internaly

	struct datavalue *query_data;
	uint64_t data_id; ///< id of the data in the dataset

	struct datavalue_read_condition *query_read_cond;
	struct datavalue_read_order *query_read_order;

	void *priv; ///< Private data of the dataset

	struct datastore *dstore;

	struct dataset *next;

};

/// Saves properties of a datastore parameter
struct datastore_param_reg {
	
	char *name; ///< Name of the parameter
	char *defval; ///< Its default value
	char *descr; ///< Description of the parameter
	struct datastore_param_reg *next; ///< Used for linking
};

/// Saves parameter value of a datastore
struct datastore_param {

	struct datastore_param_reg *type; //< Type of the parameter
	struct ptype *value; ///< Actual value of the paramater
	struct datastore_param *next; ///< Used for linking
};

struct datastore {
	int type; ///< Type of the datastore
	char *name;
	void *priv; ///< Private data of the datastore
	struct datastore_param *params; ///< Parameters of this datastore
	int started; ///< If the sdatastore is started or not
	uint32_t uid; ///< Unique ID of the datastore
	char * description; ///< Description of the datastore
	uint32_t serial; ///< Serial of the datastore
	pthread_rwlock_t lock; ///< Lock used to make each datastore operation atomic
	struct dataset *datasets; ///< List of all the datasets
	struct dataset *datasetdb; ///< Dataset containing that stores the list of datasets in the db
	struct dataset *datasetfieldsdb; ///< Dataset containing the descriptions of the fields of all the datasets

	struct datastore *next; ///< Used for linking
	struct datastore *prev; ///< Used for linking
};


/// Saves infos about a registered datastore
struct datastore_reg {

	char *name; ///< Name of the datastore
	unsigned int type; ///< Type of the datastore
	void *dl_handle; ///< Handle of the library
	unsigned int refcount; ///< Reference count
	struct datastore_param_reg *params; ///< Parameters of the datastore

	/// Pointer to the init function
	/**
	 * The init function will create allocate the privs for a new datastore instance.
	 * @param t The new instance of the datastore
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*init) (struct datastore *d);

	/// Pointer to the open function
	/**
	 * The open function will be called when starting the datastore.
	 * @param d The datastore being opened
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*open) (struct datastore *d);

	/// Pointer to the dataset_alloc function
	/**
	 * The dataste_alloc function will allocate private data for the dataset
	 * @param ds The dataset to allocate private data to
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*dataset_alloc) (struct dataset *ds);

	/// Pointer to the dataset_create function
	/**
	 * The dataste_create function will create a new dataset in the database.
	 * @param query The full description of the dataset
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*dataset_create) (struct dataset *query);

	/// Pointer to the dataset_read function
	/**
	 * The dataste_read function will read data from the dataset
	 * @param query Query
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*dataset_read) (struct dataset *query);

	/// Pointer to the dataset_write function
	/**
	 * The dataste_write function will read write to the dataset
	 * @param query Query
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*dataset_write) (struct dataset *query);

	/**
	 * The dataste_cleanup function will free the private data of the dataset
	 * @param query The dataset to free the private data from
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*dataset_cleanup) (struct dataset *ds);

	/// Pointer to the close function
	/**
	 * The close function will be called when stopping the datastore.
	 * It should free everything that open allocated.
	 * It must close all the connections it was handling.
	 * @param d The datastore being closed
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*close) (struct datastore *d);

	/// Pointer to the cleanup function
	/**
	 * The cleanup should free the memory alocated in init.
	 * @param d The datastore being opened
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*cleanup) (struct datastore *t);

	/// Pointer to the unregister function
	/**
	 * Called when unregistering the datastore.
	 * @param r What datastore to unregister
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*unregister) (struct datastore_reg *r);

};

/*@}*/


/// Register a datastore
int datastore_register(const char *datastore_name);

/// Get the type of the datastore from its name
int datastore_get_type(const char *datastore_name);

/// Register a parameter 
int datastore_register_param(struct datastore_reg *r, char *name, char *defval, char *descr);

/// Register a value for a parameter
int datastore_register_param_value(struct datastore *d, const char *name, struct ptype *value);

/// Get the name of the datastore from its type
char *datastore_get_name(int datastore_type);

/// Retreive the value of a parameter
struct ptype *datastore_get_param_value(struct datastore *d, const char *param);

/// Allocate a new instance of a datastore
struct datastore *datastore_alloc(int datastore_type);

/// Open the datastore to start processing
int datastore_open(struct datastore *d);

/// Open a dataset from a datastore
struct dataset *datastore_dataset_open(struct datastore *d, char *name, char *type, char *descr, struct datavalue_descr *dv);

/// Create a dataset in a datastore
int datastore_dataset_create(struct dataset *query);

/// Read a row from  dataset in a datastore
int datastore_dataset_read(struct dataset *query);

/// Write an entry to a dataset in a datastore
int datastore_dataset_write(struct dataset *query);

// Close a dataset
int datastore_dataset_close(struct dataset *ds);

/// Close the datastore
int datastore_close(struct datastore *d);

/// Increase the reference count on a datastore
int datastore_refcount_inc(int datastore_type);

/// Decrease the reference count on a datastore
int datastore_refcount_dec(int datastore_type);

/// Cleanup the module for unregistration
int datastore_cleanup(struct datastore *d);

/// Lock an instance of a datastore
int datastore_lock_instance(struct datastore *d, int write);

/// Unlock an instance of a datastore
int datastore_unlock_instance(struct datastore *d);

/// Get a read or write lock on the datastores
int datastore_lock(int write);

/// Release a read or write lock on the datastores
int datastore_unlock();

/// Cleanup the datastore subsystem
int datastore_cleanup();

/// Unregister a datastore
int datastore_unregister(unsigned int datastore_type);

/// Unregister all the datastores
int datastore_unregister_all();

#endif

