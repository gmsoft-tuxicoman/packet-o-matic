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

#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>

#include "target.h"
#include "conntrack.h"
#include "ptype.h"

#include "ptype_uint64.h"

struct target_reg *targets[MAX_TARGET];

static pthread_rwlock_t target_global_lock = PTHREAD_RWLOCK_INITIALIZER;

/**
 * @ingroup target_core
 */
int target_init() {

	pom_log(POM_LOG_DEBUG "Targets initialized");

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
	if (!p)
		return POM_ERR;

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
	
	if (pthread_rwlock_init(&t->lock, NULL)) {
		free(t);
		return NULL;
	}


	if (targets[target_type]->init)
		if ((*targets[target_type]->init) (t) != POM_OK) {
			free(t);
			return NULL;
		}

	t->uid = get_uid();


	t->pkt_cnt = ptype_alloc("uint64", "pkts");
	t->pkt_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN;
	t->byte_cnt = ptype_alloc("uint64", "bytes");
	t->byte_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN;

	// Default mode is the first one
	t->mode = targets[target_type]->modes;

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
		target_unlock_instance(t);
		return POM_ERR;
	}

	if (targets[t->type] && targets[t->type]->open)
		if ((*targets[t->type]->open) (t) != POM_OK) {
			target_unlock_instance(t);
			return POM_ERR;
		}

	t->started = 1;

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
		PTYPE_UINT64_INC(t->pkt_cnt, 1);
		PTYPE_UINT64_INC(t->byte_cnt, f->len);
		if (targets[t->type]->process && (*targets[t->type]->process) (t, f) == POM_ERR) {
			pom_log(POM_LOG_ERR "Target %s returned an error. Stopping it", target_get_name(t->type));
			target_unlock_instance(t);
			target_close(t);
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
		target_unlock_instance(t);
		return POM_ERR;
	}

	t->started = 0;

	int result = POM_OK;

	if (targets[t->type] && targets[t->type]->close)
		result = (*targets[t->type]->close) (t);

	return POM_OK;

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

	pthread_rwlock_destroy(&t->lock);

	ptype_cleanup(t->pkt_cnt);
	ptype_cleanup(t->byte_cnt);

	target_unlock_instance(t);

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
int target_file_open(struct layer *l, char *filename, int flags, mode_t mode) {

	char buffer[NAME_MAX + 1];
	memset(buffer, 0, NAME_MAX + 1);

	if (l)
		layer_field_parse(l, filename, buffer, NAME_MAX);
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

