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

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#include "target.h"
#include "conntrack.h"
#include "ptype.h"
#include "main.h"
#include "core_param.h"
#include "perf.h"

#include "ptype_uint64.h"
#include "ptype_string.h"
#include "ptype_bool.h"

struct target_reg *targets[MAX_TARGET];

static pthread_rwlock_t target_global_lock = PTHREAD_RWLOCK_INITIALIZER;

static struct ptype *param_autostart_datastore = NULL;

static struct perf_class *target_perf_class = NULL;

/**
 * @ingroup target_core
 */
int target_init() {

	pom_log(POM_LOG_DEBUG "Targets initialized");
	param_autostart_datastore = ptype_alloc("bool", NULL);
	if (!param_autostart_datastore)
		return POM_ERR;
	
	core_register_param("target_autostart_datastore", "yes", param_autostart_datastore, "Automatically start a datastore being used by a target", NULL);

	target_perf_class = perf_register_class("target");

	return POM_OK;

}

/**
 * @ingroup target_core
 * @param target_name Name of the target to register
 * @return The type of the target or POM_ERR on failure.
 */
int target_register(const char *target_name) {

	int i;

	
	for (i = 0; i < MAX_TARGET; i++) {
		if (targets[i] != NULL) {
			if (strcmp(targets[i]->name, target_name) == 0) {
				return i;
			}
		} else {
			int (*register_my_target) (struct target_reg *);

			void *handle = NULL;
			register_my_target = lib_get_register_func("target", target_name, &handle);

			if (!register_my_target) {
				return POM_ERR;
			}

			struct target_reg *my_target = malloc(sizeof(struct target_reg));
			memset(my_target, 0, sizeof(struct target_reg));

			targets[i] = my_target;
			my_target->type = i;
	
			match_lock(1); // Allow safe registration of the matches
			if ((*register_my_target) (my_target) != POM_OK) {
				match_unlock();
				pom_log(POM_LOG_ERR "Error while loading target %s. could not register target !", target_name);
				targets[i] = NULL;
				free(my_target);
				return POM_ERR;
			}

			match_unlock();


			targets[i]->name = malloc(strlen(target_name) + 1);
			strcpy(targets[i]->name, target_name);
			targets[i]->dl_handle = handle;

			pom_log(POM_LOG_DEBUG "Target %s registered", target_name);
			
			return i;
		}
	}


	return POM_ERR;

}

/**
 * @ingroup target_api
 * @param target_type Type of the target to register the mode to
 * @param name Name of the mode
 * @param descr Description of the mode
 * @return The registered mode or NULL on error.
 */
struct target_mode *target_register_mode(int target_type, const char *name, const char *descr) {

	if (!targets[target_type])
		return NULL;

	struct target_mode *mode = malloc(sizeof(struct target_mode));
	memset(mode, 0, sizeof(struct target_mode));
	
	mode->name = malloc(strlen(name) + 1);
	strcpy(mode->name, name);
	mode->descr = malloc(strlen(descr) + 1);
	strcpy(mode->descr, descr);
	
	if (!targets[target_type]->modes) {
		targets[target_type]->modes = mode;
	} else {
		struct target_mode *tmpm = targets[target_type]->modes;
		while (tmpm->next)
			tmpm = tmpm->next;
		tmpm->next = mode;
	}

	return mode;

}

/**
 * @ingroup target_api
 * @param mode The mode to register a parameter to
 * @param name The name of the parameter
 * @param defval Default value
 * @param descr Description
 * @return POM_OK on success, POM_ERR on failure.
 */
int target_register_param(struct target_mode *mode, char *name, char *defval, char *descr) {

	if (!mode)
		return POM_ERR;

	struct target_param_reg *param = malloc(sizeof(struct target_param_reg));
	memset(param, 0, sizeof(struct target_param_reg));

	param->name = malloc(strlen(name) + 1);
	strcpy(param->name, name);
	param->defval = malloc(strlen(defval) + 1);
	strcpy(param->defval, defval);
	param->descr = malloc(strlen(descr) + 1);
	strcpy(param->descr, descr);

	if (!mode->params) {
		mode->params = param;
	} else {
		struct target_param_reg *tmp = mode->params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = param;
	}

	return POM_OK;
}

/**
 * @ingroup target_api
 * @param t The target which is registering the value
 * @param mode The mode to which the parameter of the value belongs
 * @param name Name of the parameter to register its value
 * @param value The actual value
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int target_register_param_value(struct target *t, struct target_mode *mode, const char *name, struct ptype *value) {

	if (!t || !mode || !value)
		return POM_ERR;

	struct target_param_reg *p = mode->params;
	while (p) {
		if (!strcmp(p->name, name))
			break;
		p = p->next;
	}
	if (!p) {
		pom_log(POM_LOG_ERR "Error while registering parameter value for param %s. This parameter isn't registered yet", name);
		return POM_ERR;
	}

	if (ptype_parse_val(value, p->defval) != POM_OK)
		return POM_ERR;

	struct target_param *tp = malloc(sizeof(struct target_param));
	memset(tp, 0, sizeof(struct target_param));

	tp->type = p;
	tp->value = value;


	struct target_param *tmp = t->params;

	if (!tmp) {
		t->params = tp;
	} else {
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = tp;

	}

	return POM_OK;


}

/**
 * @ingroup target_core
 * @param target_type Type of the target to create a new instance
 * @return The new instance of the target or NULL on failure.
 */
struct target *target_alloc(int target_type) {

	if (!targets[target_type]) {
		pom_log(POM_LOG_ERR "Target type %u is not registered", target_type);
		return NULL;
	}
	struct target *t = malloc(sizeof(struct target));
	memset(t, 0, sizeof(struct target));

	t->type = target_type;
	
	// Init the lock
	if (pthread_rwlock_init(&t->lock, NULL)) {
		free(t);
		return NULL;
	}

	// Init the target internal stuff
	t->uid = uid_get_new();

	// Default mode is the first one
	t->mode = targets[target_type]->modes;
	
	t->perfs = perf_register_instance(target_perf_class, t);
	t->perf_pkts = perf_add_item(t->perfs, "pkts", perf_item_type_counter, "Number of packets processed");
	t->perf_bytes = perf_add_item(t->perfs, "bytes", perf_item_type_counter, "Number of bytes processed");
	t->perf_uptime = perf_add_item(t->perfs, "uptime", perf_item_type_uptime, "Time for which the target has been started");

	if (targets[target_type]->init) {
		if ((*targets[target_type]->init) (t) != POM_OK) {
			free(t);
			return NULL;
		}
	}

	targets[target_type]->refcount++;
		
	return t;
}

/**
 * @ingroup target_api
 * @param t Target to set the mode to
 * @param mode_name Mode to set
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int target_set_mode(struct target *t, const char *mode_name) {

	if (!t)
		return POM_ERR;
	
	struct target_mode *mode = targets[t->type]->modes;
	while (mode) {
		if (!strcmp(mode->name, mode_name)) {
			t->mode = mode;
			return POM_OK;
		}
		mode = mode->next;
	}

	return POM_ERR;
}

/**
 * @ingroup target_core
 * @param t Target to get the value from
 * @param param Name of the parameter to get the value from
 * @return The value of the parameter or NULL on error.
 */
struct ptype *target_get_param_value(struct target *t, const char *param) {

	if (!t)
		return NULL;

	if (!t->mode)
		return NULL;

	struct target_param_reg *pr = t->mode->params;
	while (pr) {
		if (!strcmp(pr->name, param))
			break;
		pr = pr->next;
	}

	if (!pr)
		return NULL;

	struct target_param *p = t->params;
	while (p) {
		if (p->type == pr)
			break;

		p = p->next;
	}
	
	if (!p) 
		return NULL;

	return p->value;

}

/**
 * @ingroup target_core
 * @param target_type Type of the target
 * @return The name of the target or NULL on error.
 */
char *target_get_name(int target_type) {

	if (!targets[target_type])
		return NULL;

	return targets[target_type]->name;

}

/**
 * @ingroup target_core
 * @param target_name Name of the target
 * @return The type of the target or POM_ERR on error.
 */
int target_get_type(char* target_name) {

	int i;
	for (i = 0; i < MAX_TARGET; i++)
		if (targets[i] && strcmp(targets[i]->name, target_name) == 0)
			return i;

	return POM_ERR;

}

/**
 * @ingroup target_core
 * This function will grab a write lock on the target instance.
 * @param t Target to open
 * @return POM_OK on success, POM_ERR on failure.
 */
int target_open(struct target *t) {

	if (!t)
		return POM_ERR;

	if (t->started) {
		return POM_ERR;
	}

	if (targets[t->type] && targets[t->type]->open)
		if ((*targets[t->type]->open) (t) != POM_OK) {
			// Make sure we close the datastores already open
			struct target_dataset *ds = NULL;
			while (t->datasets) {
				ds = t->datasets;
				t->datasets = t->datasets->next;
				if (ds->dset && ds->dset->open) {
					ds->dset->query_data = ds->orig_ds_data;
					datastore_dataset_close(ds->dset);
				}
				free(ds->name);
				free(ds);
			}
			return POM_ERR;
		}

	struct ptype* param_reset_counters_on_restart = core_get_param_value("reset_counters_on_item_restart");
	if (PTYPE_BOOL_GETVAL(param_reset_counters_on_restart)) {
		perf_instance_items_val_reset(t->perfs);
	} else {
		perf_item_val_uptime_restart(t->perf_uptime);
	}


	t->started = 1;
	t->serial++;
	if (t->parent_serial) {
		(*t->parent_serial)++;
		main_config->target_serial++;
	}

	return POM_OK;

}

/**
 * @ingroup target_core
 * If the target returns POM_ERR, it will be closed.
 * This function will grab a read lock on the target instance.
 * @param t Target to send the packet to
 * @param f The frame to process
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int target_process(struct target *t, struct frame *f) {

	target_lock_instance(t, 0);
	if (t->started) {
		perf_item_val_inc(t->perf_pkts, 1);
		perf_item_val_inc(t->perf_bytes, f->len);
		if (targets[t->type]->process && (*targets[t->type]->process) (t, f) == POM_ERR) {
			pom_log(POM_LOG_ERR "Target %s returned an error. Stopping it", target_get_name(t->type));
			target_close(t);
			target_unlock_instance(t);
			return POM_ERR;
		}
	}
	target_unlock_instance(t);
	return POM_OK;

}

/**
 * @ingroup target_core
 * This function will grab a write lock on the target instance.
 * @param t Target to close
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int target_close(struct target *t) {

	if (!t)
		return POM_ERR;

	if (!t->started) {
		return POM_ERR;
	}

	t->started = 0;

	int result = POM_OK;

	if (targets[t->type] && targets[t->type]->close)
		result = (*targets[t->type]->close) (t);

	while (t->datasets) {
		struct target_dataset *ds = t->datasets;
		t->datasets = t->datasets->next;
		if (ds->dset && ds->dset->open) {
			ds->dset->query_data = ds->orig_ds_data;
			datastore_dataset_close(ds->dset);
		}
		free(ds->name);
		free(ds);
	}

	perf_item_val_uptime_stop(t->perf_uptime);

	t->serial++;
	if (t->parent_serial) {
		(*t->parent_serial)++;
		main_config->target_serial++;
	}

	return result;

}

/**
 * @ingroup target_core
 * The target MUST be write locked when calling this function.
 * @param t Target to cleanup
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int target_cleanup_module(struct target *t) {

	if (!t)
		return POM_ERR;


	if (targets[t->type]) {
		if (targets[t->type]->cleanup)
			(*targets[t->type]->cleanup) (t);
		struct target_param *p = t->params;
		while (p) {
			p = p->next;
			free(t->params);
			t->params = p;
		}
		targets[t->type]->refcount--;
	}

	perf_unregister_instance(target_perf_class, t->perfs);

	target_unlock_instance(t);
	pthread_rwlock_destroy(&t->lock);

	if (t->description)
		free(t->description);

	uid_release(t->uid);

	free (t);

	return POM_OK;

}

/**
 * @ingroup target_core
 * @param target_type Target type to unregister
 * @return POM_OK on success, POM_ERR on failure.
 */
int target_unregister(int target_type) {

	if (!targets[target_type])
		return POM_ERR;

	if (targets[target_type]->refcount) {
		pom_log(POM_LOG_WARN "Warning, reference count not 0 for target %s", targets[target_type]->name);
		return POM_ERR;
	}

	if (targets[target_type]->unregister)
		(*targets[target_type]->unregister) (targets[target_type]);

	struct target_mode *mode = targets[target_type]->modes;

	while (mode) {
		
		struct target_param_reg *p = mode->params;
		while (p) {
			free(p->name);
			free(p->defval);
			free(p->descr);
			p = p->next;
			free(mode->params);
			mode->params = p;
		}
		
		free(mode->name);
		free(mode->descr);
		mode = mode->next;
		free(targets[target_type]->modes);
		targets[target_type]->modes = mode;
	}

	if(dlclose(targets[target_type]->dl_handle))
		pom_log(POM_LOG_WARN "Error while closing library of target %s", targets[target_type]->name);
	free(targets[target_type]->name);
	free(targets[target_type]);
	targets[target_type] = NULL;

	return POM_OK;

}

/**
 * @ingroup target_core
 * @return POM_OK on sucess, POM_ERR on error.
 */
int target_unregister_all() {

	int i = 0;
	int result = POM_OK;

	for (; i < MAX_TARGET; i++) {
		if (targets[i] && target_unregister(i) == POM_ERR)
			result = POM_ERR;
	}

	return result;

}

/**
 * @ingroup target_core
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int target_cleanup() {

	ptype_cleanup(param_autostart_datastore);	

	return POM_OK;

}

/**
 * @ingroup target_core
 * This function will process the SIGHUP event for a target
 * @param t Target to process
 * @return POM_OK on sucess, POM_ERR on failure.
 */
int target_sighup(struct target *t) {

	target_lock_instance(t, 0);
	if (t->started) {
		if (targets[t->type]->sighup && (*targets[t->type]->sighup) (t) == POM_ERR) {
			pom_log(POM_LOG_ERR "Target %s returned an error while sending SIGHUP. Stopping it", target_get_name(t->type));
			target_close(t);
			target_unlock_instance(t);
			return POM_ERR;
		}
	}
	target_unlock_instance(t);
	return POM_OK;

}

/**
 * @ingroup target_core
 */
void target_print_help() {

	int i;


	for (i = 0; i < MAX_TARGET; i++) {
		if (!targets[i])
			continue;
		printf("* TARGET %s *\n", targets[i]->name);

		if (!targets[i]->modes) {
			printf("No parameter for this target\n");
		} else {
			struct target_mode *m = targets[i]->modes;
			while (m) {
				printf("Mode %s : %s\n", m->name, m->descr);
				struct target_param_reg *p = m->params;
				if (!p) {
					printf("  No parameter for this mode\n");
				} else {
					while (p) {
						printf("  %s : %s (Default : %s)\n", p->name, p->descr, p->defval);
						p = p->next;
					}
				}
				m = m->next;
			}


		}
		printf("\n");
	}
}

/**
 * @ingroup target_api
 * @param l Layer of the packet that correspond to the file
 * @param filename Name of the file that may contain variables to be expended
 * @param flags Flags as documented in open(2)
 * @param mode Mode as documented in open(2)
 * @return The file descriptor on success, POM_ERR on failure.
 */
int target_file_open(struct layer *l, struct timeval *tv, char *filename, int flags, mode_t mode) {

	char buffer[NAME_MAX + 1];
	memset(buffer, 0, NAME_MAX + 1);

	if (l)
		layer_field_parse(l, tv, filename, buffer, NAME_MAX);
	else
		strncpy(buffer, filename, NAME_MAX);

	pom_log(POM_LOG_TSHOOT "Opening file %s", buffer);

	char *slash = buffer;
	if (*slash == '/') // we assume that the root directory exists :)
		slash++;

	slash = strchr(slash, '/');
	while (slash) {
		*slash = 0;
		struct stat stats;
		if (stat(buffer, &stats)) {
			switch (errno) {
				case ENOENT:
					mkdir(buffer, 00777);
					break;
				default:
					return -1;

			}
		}
		*slash = '/';
		slash = strchr(slash + 1, '/');
	}

	return open(buffer, flags, mode);


}
/**
 * @ingroup target_core
 * @param t Target to lock
 * @param write Get a write or read lock
 * @return POM_OK on success, POM_ERR on failure
 */
int target_lock_instance(struct target *t, int write) {

	int result = 0;

	if (write) {
		result = pthread_rwlock_wrlock(&t->lock);
	} else {
		result = pthread_rwlock_rdlock(&t->lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking a target instance lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

/**
 * @ingroup target_core
 * @param t Target to unlock
 * @return POM_OK on success, POM_ERR on failure
 */
int target_unlock_instance(struct target *t) {

	if (pthread_rwlock_unlock(&t->lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the target lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;
}

/**
 * @ingroup target_core
 * @param write Set to 1 if targets will be modified, 0 if not
 * @return POM_OK on success, POM_ERR on failure.
 */
int target_lock(int write) {

	int result = 0;
	if (write) {
		result = pthread_rwlock_wrlock(&target_global_lock);
	} else {
		result = pthread_rwlock_rdlock(&target_global_lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking the target lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

/**
 * @ingroup target_core
 * @return POM_OK on success, POM_ERR on failure.
 */
int target_unlock() {

	if (pthread_rwlock_unlock(&target_global_lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the target lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

struct target_dataset *target_open_dataset(struct target *t, char *name, char *descr, char *ds_path, struct datavalue_descr *fields) {


	struct target_dataset *ds = t->datasets;

	while (ds) {
		if (!strcmp(ds->name, name)) // Dataset already opened
			return NULL;
		ds = ds->next;
	}

	// Compute the name of the datastore and the dataset
	if (!strlen(ds_path))
		return NULL;

	char *datastore_name = malloc(strlen(ds_path) + 1);
	strcpy(datastore_name, ds_path);

	char *dataset_name = strchr(datastore_name, '/');

	if (dataset_name) { // Append the name to the prefix
		datastore_name = realloc(datastore_name, strlen(datastore_name) + strlen(name) + 2);
		strcat(datastore_name, "_");
		strcat(datastore_name, name);
		// string reallocated, need the new position of '/'
		dataset_name = strchr(datastore_name, '/');
		*dataset_name = 0;
		dataset_name++;
	} else {
		dataset_name = name;
	}

	// Open the datastore
	

	main_config_datastores_lock(0);

	struct datastore *dstore = main_config->datastores;
	while (dstore) {
		if (!strcmp(dstore->name, datastore_name)) {
			datastore_lock_instance(dstore, 1);
			if (!dstore->started) {
				if (PTYPE_BOOL_GETVAL(param_autostart_datastore)) {
					if (datastore_open(dstore) == POM_ERR) {
						datastore_unlock_instance(dstore);
						main_config_datastores_unlock();
						free(datastore_name);
						return NULL;
					}
				} else {
					pom_log(POM_LOG_WARN "Datastore %s not started and target_autostart_datastore is set to no. Nothing will be saved", dstore->name);
					datastore_unlock_instance(dstore);
					main_config_datastores_unlock();
					free(datastore_name);
					return NULL;
				}
			}
			break;
		}

		dstore = dstore->next;
	}
	main_config_datastores_unlock();

	if (!dstore) {
		pom_log(POM_LOG_ERR "Unable to find datastore %s", datastore_name);
		return NULL;
	}

	// Found the right datastore. Open the dataset now
	
	char *dataset_type = malloc(strlen(targets[t->type]->name) + strlen("_") + strlen(name) + 1);
	strcpy(dataset_type, targets[t->type]->name);
	strcat(dataset_type, "_");
	strcat(dataset_type, name);

	
	struct target_dataset *res = malloc(sizeof(struct target_dataset));
	memset(res, 0, sizeof(struct target_dataset));
	res->dset = datastore_dataset_open(dstore, dataset_name, dataset_type, descr, fields, target_dataset_error);
	datastore_unlock_instance(dstore);

	free(dataset_type);
	free(datastore_name);

	if (!res->dset) {
		free(res);
		return NULL;
	}

	res->name = malloc(strlen(name) + 1);
	strcpy(res->name, name);

	// Targets should alloc their own datavalue
	res->orig_ds_data = res->dset->query_data;
	res->dset->query_data = NULL;

	res->next = t->datasets;
	t->datasets = res;

	return res;

}


struct datavalue *target_alloc_dataset_values(struct target_dataset *ds) {
	
	struct datavalue *res, *dv = ds->orig_ds_data;

	unsigned int count, i;

	// Count the number of fields
	for (count = 0; dv[count].name; count++);
	res = malloc(sizeof(struct datavalue) * (count + 1));
	memcpy(res, dv, sizeof(struct datavalue) * (count + 1));

	for (i = 0; i < count; i++)
		res[i].value = ptype_alloc_from(dv[i].value);

	return res;
}


int target_cleanup_dataset_values(struct datavalue *dv) {

	unsigned int i;
	for (i = 0; dv[i].name; i++)
		ptype_cleanup(dv[i].value);

	free(dv);

	return POM_OK;
}


int target_write_dataset(struct target_dataset *ds, struct datavalue *dv) {

	if (!ds->dset)
		return POM_ERR;

	ds->dset->query_data = dv;
	int res = datastore_dataset_write(ds->dset);
	if (ds->dset) // Datastore could have been closed in the meantime
		ds->dset->query_data = NULL;
	return res;

}

int target_dataset_error(struct dataset *dset) {

	// This is ugly and slow but it's not supposed to happen ...

	struct rule_list *rl = main_config->rules;

	while (rl) {

		struct target *t = rl->target;
		while (t) {

			struct target_dataset *tds = t->datasets;
			while (tds) {
				if (tds->dset == dset) {
					int res = pthread_rwlock_trywrlock(&t->lock);
					if (res == EBUSY) {
						// Target is busy, probably processing. Let's close the dataset
						tds->dset->query_data = tds->orig_ds_data;
						datastore_dataset_close(tds->dset);
						tds->dset = NULL;
					} else if (!res) {
						// Target is not busy, let's close it
						target_close(t);
						target_unlock_instance(t);
					} else {
						// Locking operation failed
						pom_log(POM_LOG_ERR "Error while locking a target instance lock");
						abort();
						return POM_ERR;

					}
					return POM_OK;
				}

				tds = tds->next;
			}
			t = t->next;
		}
		rl = rl->next;
	}

	return POM_OK;
}
