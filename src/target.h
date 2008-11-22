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


#ifndef __TARGET_H__
#define __TARGET_H__

#include "conntrack.h"
#include "match.h"
#include "ptype.h"
#include "expectation.h"
#include "datastore.h"

/**
 * @defgroup target_api Target API
 */
/*@{*/

/// This structure saves the properties of a target parameter
struct target_param_reg {

	char *name; ///< Name of the parameter
	char *defval; ///< Its default value
	char *descr; ///< Description of the parameter
	struct target_param_reg *next; ///< Used for linking

};

/// This structure describe a parameter instance for a target
struct target_param {

	struct target_param_reg *type; ///< Type of the parameter
	struct ptype *value; ///< Actual value of the paramater
	struct target_param *next; ///< Used for linking

};

/// This structure is used by targets to specify how they will save the data 
struct target_dataset_reg {
	char *name; ///< Dataset name
	char *descr; ///< Description
	struct datavalue_descr *fields; ///< NULL terminated array of fields
	struct target_dataset_reg *next; ///< Used for linking

};

/// Instance of a dataset for a target
struct target_dataset {
	struct target_dataset_reg *type; ///< Common info about the datastore
	struct ptype *ds_path; ///< Ptype for the dataset parameter value
	struct dataset *dset; ///< Pointer to the dataset
	struct target_dataset *next; ///<  Used for linking

};

/// This structure is used to save the target's modes
struct target_mode {

	char *name; ///< Name of the mode
	char *descr; ///< Description of the mode
	struct target_param_reg *params; ///< Parameters associated with this mode
	struct target_dataset_reg *datasets; ///< Datasets associated with this mode
	struct target_mode *next; ///< Used for linking

};


/// This structure holds all the information about a registered target
/**
 * A target should provide at least the function process.
 */
struct target_reg {
	
	char *name; ///< Name of the target
	int type; ///< It's type
	void *dl_handle; ///< Handle of the library
	unsigned int refcount; ///< Reference count
	struct target_mode *modes; ///< Registered modes of the target

	/// Pointer to the init function
	/**
	 * The init function will create allocate the privs for a new target instance.
	 * @param t The new instance of the target
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*init) (struct target *t);

	/// Pointer to the open function
	/**
	 * The open function will be called when starting the target.
	 * @param t The target being opened
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*open) (struct target *t);

	/// Pointer to the process function
	/**
	 * The process function will be called for each packet that needs to be processed.
	 * If POM_ERR is returned, the target will be stopped.
	 * @param t The target which has to process the target
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*process) (struct target* t, struct frame *f);

	/// Pointer to the close function
	/**
	 * The close function will be called when stopping the target.
	 * It should free everything that open allocated.
	 * It must close all the connections it was handling.
	 * @param t The target being closed
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*close) (struct target *t);

	/// Pointer to the cleanup function
	/**
	 * The cleanup should free the memory alocated in init.
	 * @param t The target being opened
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*cleanup) (struct target *t);

	/// Pointer to the unregister function
	/**
	 * Called when unregistering the target.
	 * @param r What target to unregister
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*unregister) (struct target_reg *r);
};

/// This structure describe an instance of a target
struct target {
	int type; ///< Type of the target
	void *target_priv; ///< Private data of this instance
	struct target_param *params; ///< Parameters of this target
	struct target_mode *mode; ///< Mode of this target
	int matched; ///< Used internally for rules processing
	int started; ///< If the starget is started or not
	uint32_t uid; ///< Unique ID of the target
	uint32_t serial; ///< Serial of the target
	uint32_t *parent_serial; ///< Serial stored at the rule level if any
	char * description; ///< Description of the target
	pthread_rwlock_t lock; ///< Lock used to make each target operation atomic
	struct target_dataset *datasets; ///< Datasets used by the target

	struct ptype* pkt_cnt; ///< Number of packets processed by this target
	struct ptype* byte_cnt; ///< Number of bytes processed by this target

	struct target *next; ///< Used for linking
	struct target *prev; ///< Used for linking
};
/*@}*/

/**
 * @defgroup target_core Target core functions
 */
/*@{*/

/// Maximum number of registered targets
#define MAX_TARGET 16

/// Name of the parameter for the datastores
#define TARGET_DATASTORE_PARAM_NAME "datastore_path"

/// Contains all the registered targets
extern struct target_reg *targets[MAX_TARGET];

/*@}*/

/// Init the input subsystem
int target_init();

/// Register a new target
int target_register(const char *target_name);

/// Register a mode for a specific target
struct target_mode *target_register_mode(int target_type, const char *name, const char *descr);

/// Register a parameter for a specific mode
int target_register_param(struct target_mode *mode, char *name, char *defval, char *descr);

/// Register a value for a parameter
int target_register_param_value(struct target *t, struct target_mode *mode, const char *name, struct ptype *value);

/// Allocate a new instance of a target
struct target *target_alloc(int target_type);

/// The the neede mode on the target
int target_set_mode(struct target *t, const char *mode_name);

/// Retreive the value of a parameter
struct ptype *target_get_param_value(struct target *t, const char *param);

/// Get the target name from its type
char *target_get_name(int target_type);

/// Get the target type from its name
int target_get_type(char* target_name);

/// Open the target to start processing
int target_open(struct target *t);

/// Process one packet
int target_process(struct target *t, struct frame *f);

/// Close the target
int target_close(struct target *t);

/// Cleanup the module for unregistration
int target_cleanup_module(struct target *t);

/// Unregister a specific target
int target_unregister(int target_type);

/// Unregister all the targets
int target_unregister_all();

/// Print the help of the loaded targets
void target_print_help();

/// Cleanup the target subsystem
int target_cleanup();

/// Open a file for a target
int target_file_open(struct layer *l, char *filename, int flags, mode_t mode);

/// Lock an instance of a target
int target_lock_instance(struct target *t, int write);

/// Unlock an instance of a target
int target_unlock_instance(struct target *t);

/// Get a read or write lock on the targets
int target_lock(int write);

/// Release a read or write lock on the targets
int target_unlock();

/// Register a dataset for a target mode
int target_register_dataset(struct target_mode *mode, char *name, char *descr, struct datavalue_descr *fields);

/// Return the instance of a previously registered dataset
struct target_dataset *target_get_dataset_instance(struct target *t, char *name);

/// Return the struct datavalue associated with the registered parameters
struct datavalue *target_get_dataset_values(struct target_dataset *ds);

/// Write data in the datastore
int target_write_dataset(struct target_dataset *ds, struct frame *f);

#endif
