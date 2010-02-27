/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2009-2010 Guy Martin <gmsoft@tuxicoman.be>
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

#include "perf.h"


struct perf_class *perfs_head = NULL;


struct perf_class *perf_register_class(char *class_name) {

	struct perf_class *tmp = perfs_head;
	while (tmp) {
		if (!strcasecmp(class_name, tmp->name))
			break;
		tmp = tmp->next;
	}
	
	if (tmp) {
		pom_log(POM_LOG_WARN "Perf class %s already registered", class_name);
		return tmp;
	}

	tmp = malloc(sizeof(struct perf_class));
	memset(tmp, 0, sizeof(struct perf_class));

	tmp->name = malloc(strlen(class_name) + 1);
	strcpy(tmp->name, class_name);

	tmp->next = perfs_head;
	perfs_head = tmp;

	pom_log(POM_LOG_DEBUG "Registered class %s", class_name);

	return tmp;
}


struct perf_instance *perf_register_instance(struct perf_class *class, void *object) {

	struct perf_instance *tmp = class->instances;
	while (tmp) {
		if (tmp->object == object)
			break;
		tmp = tmp->next;
	}

	if (tmp) {
		pom_log(POM_LOG_WARN "Object 0x%llX already added to class %s", object, class->name);
		return tmp;
	}

	
	tmp = malloc(sizeof(struct perf_instance));
	memset(tmp, 0, sizeof(struct perf_instance));
	
	if (pthread_rwlock_init(&tmp->lock, NULL)) {
		pom_log(POM_LOG_ERR "Unable to initialize the performance instance lock");
		free(tmp);
		return NULL;
	}

	tmp->object = object;

	tmp->next = class->instances;
	if (tmp->next)
		tmp->next->prev = tmp;

	class->instances = tmp;

	return tmp;

}

int perf_instance_lock(struct perf_instance *instance, int write) {

	int result = 0;

	if (write) {
		result = pthread_rwlock_wrlock(&instance->lock);
	} else {
		result = pthread_rwlock_rdlock(&instance->lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking the perf instance lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;
}

int perf_instance_unlock(struct perf_instance *instance) {

	if (pthread_rwlock_unlock(&instance->lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the perf instance lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;
}

int perf_item_lock(struct perf_item *itm, int write) {

	int result = 0;

	if (write) {
		result = pthread_rwlock_wrlock(&itm->lock);
	} else {
		result = pthread_rwlock_rdlock(&itm->lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking the perf item lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;
}

int perf_item_unlock(struct perf_item *itm) {

	if (pthread_rwlock_unlock(&itm->lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the perf item lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;
}

struct perf_item *perf_add_item(struct perf_instance *instance, char *name, enum perf_item_type type, char *descr) {

	perf_instance_lock(instance, 1);

	struct perf_item *tmp = instance->items, *tmp_last = NULL;
	while (tmp) {
		if (!strcmp(tmp->name, name)) {
			pom_log(POM_LOG_WARN "Item %s already added to instance", name);
			perf_instance_unlock(instance);
			return NULL;
		}
		tmp_last = tmp;
		tmp = tmp->next;
	}

	tmp = malloc(sizeof(struct perf_item));
	memset(tmp, 0, sizeof(struct perf_item));

	if (pthread_rwlock_init(&tmp->lock, NULL)) {
		pom_log(POM_LOG_ERR "Unable to initialize the performance item lock");
		free(tmp);
		return NULL;
	}

	tmp->name = strdup(name);
	tmp->type = type;
	tmp->descr = strdup(descr);
	tmp->instance = instance;

	if (type == perf_item_type_uptime)
		tmp->value = PERF_UPTIME_STOPPED;

	if (!tmp_last) {
		instance->items = tmp;
	} else {
		tmp_last->next = tmp;
		tmp->prev = tmp_last;
	}
	
	perf_instance_unlock(instance);

	return tmp;

}

int perf_item_set_update_hook(struct perf_item *itm, int (*update_hook) (struct perf_item *itm, void *priv), void *priv) {

	perf_item_lock(itm, 1);

	if (itm->type == perf_item_type_uptime) {
		perf_item_unlock(itm);
		pom_log(POM_LOG_ERR "Cannot set an update hook on an uptime item");
		return POM_ERR;
	}

	itm->update_hook = update_hook;
	itm->hook_priv = priv;

	perf_item_unlock(itm);

	return POM_OK;
}

int perf_remove_item(struct perf_instance *instance, struct perf_item *itm) {

	perf_instance_lock(instance, 1);

	if (!itm->prev) {
		instance->items = itm;
	} else {
		itm->prev->next = itm->next;
	}

	if (itm->next)
		itm->next->prev = itm->prev;

	free(itm->name);
	free(itm->descr);
	pthread_rwlock_destroy(&itm->lock);
	free(itm);

	perf_instance_unlock(instance);

	return POM_OK;
}

int perf_unregister_instance(struct perf_class *class, struct perf_instance *instance) {


	struct perf_instance *tmp = class->instances;
	while (tmp) {
		if (tmp == instance)
			break;
		tmp = tmp->next;
	}

	if (!tmp) {
		pom_log(POM_LOG_WARN "Instance 0x%llX not found in class %s", instance, class->name);
		return POM_ERR;
	}

	perf_instance_lock(instance, 1);
	struct perf_item *itm = tmp->items;
	while (itm) {
		struct perf_item *del_item = itm;
		itm = itm->next;
		free(del_item->name);
		free(del_item->descr);
		pthread_rwlock_destroy(&del_item->lock);
		free(del_item);
	}

	if (!tmp->prev)
		class->instances = tmp->next;
	else
		tmp->prev->next = tmp->next;

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	perf_instance_unlock(instance);

	pthread_rwlock_destroy(&tmp->lock);
	free(tmp);


	return POM_OK;
}

int perf_cleanup() {
	
	while (perfs_head) {
		struct perf_class *tmp = perfs_head;
		perfs_head = perfs_head->next;
		free(tmp->name);
		if (tmp->instances)
			pom_log(POM_LOG_WARN "Warning not all instances from perf_class were unregistered, some memory will not be freed");
		free(tmp);
	}

	return POM_OK;
}


int perf_item_val_reset(struct perf_item *itm) {

	perf_item_lock(itm, 1);

	if (itm->type == perf_item_type_uptime) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		// Time is stored in centisecs
		itm->value = ((uint64_t)tv.tv_sec * 100LLU) + ((uint64_t)tv.tv_usec / 10000LLU);
	} else {
		itm->value = 0;
	}

	perf_item_unlock(itm);
	return POM_OK;
}

int perf_instance_items_val_reset(struct perf_instance *instance) {

	perf_instance_lock(instance, 0);

	struct perf_item *itm = instance->items;
	while (itm) {
		perf_item_val_reset(itm);
		itm = itm->next;
	}

	perf_instance_unlock(instance);

	return POM_OK;
}

uint64_t perf_item_val_inc(struct perf_item *itm, int64_t inc) {

	perf_item_lock(itm, 1);
	if (itm->type == perf_item_type_uptime) {
		pom_log(POM_LOG_WARN "Cannot increment item of type uptime");
	} else if (itm->update_hook) {
		pom_log(POM_LOG_WARN "Cannot increment item when it has an update hook");
	} else {
		itm->value += inc;
	}

	if (itm->type == perf_item_type_counter && inc < 0)
		pom_log(POM_LOG_WARN "Trying to decrease the value of a counter");

	perf_item_unlock(itm);
	return itm->value;
}

int perf_item_val_uptime_stop(struct perf_item *itm) {

	perf_item_lock(itm, 1);
	if (itm->type != perf_item_type_uptime) {
		perf_item_unlock(itm);
		pom_log(POM_LOG_WARN "Warning, trying to stop uptime on a non uptime performance item");
		return POM_ERR;
	}

	if (itm->value & PERF_UPTIME_STOPPED) {
		perf_item_unlock(itm);
		pom_log(POM_LOG_WARN "Warning, uptime already stopped");
		return POM_ERR;
	}

	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = ((uint64_t)tv.tv_sec * 100LLU) + ((uint64_t)tv.tv_usec / 10000LLU);
	itm->value = (now - itm->value) | PERF_UPTIME_STOPPED;

	perf_item_unlock(itm);

	return POM_OK;

}

int perf_item_val_uptime_restart(struct perf_item *itm) {

	perf_item_lock(itm, 1);
	if (itm->type != perf_item_type_uptime) {
		perf_item_unlock(itm);
		pom_log(POM_LOG_WARN "Warning, trying to restart uptime on a non uptime performance item");
		return POM_ERR;
	}

	if (!(itm->value & PERF_UPTIME_STOPPED)) {
		perf_item_unlock(itm);
		pom_log(POM_LOG_WARN "Warning, uptime already started");
		return POM_ERR;
	}

	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = ((uint64_t)tv.tv_sec * 100LLU) + ((uint64_t)tv.tv_usec / 10000LLU);
	itm->value = now - (itm->value & ~PERF_UPTIME_STOPPED);

	perf_item_unlock(itm);

	return POM_OK;

}

uint64_t perf_item_val_get_raw(struct perf_item *itm) {

	perf_item_lock(itm, 1);
	uint64_t val = 0;
	if (itm->type == perf_item_type_uptime) {

		// Return raw value if uptime count was stopped
		if (itm->value & PERF_UPTIME_STOPPED) {
			uint64_t val = itm->value & ~PERF_UPTIME_STOPPED;
			perf_item_unlock(itm);
			return val;
		}

		struct timeval tv;
		gettimeofday(&tv, NULL);
		uint64_t now = ((uint64_t)tv.tv_sec * 100LLU) + ((uint64_t)tv.tv_usec / 10000LLU);
		uint64_t val = now - itm->value;
		perf_item_unlock(itm);
		return val;
	}

	if (itm->update_hook) {
		perf_item_unlock(itm);
		// We need a write lock
		perf_item_lock(itm, 1);
		if (itm->update_hook(itm, itm->hook_priv) == POM_ERR) {
			pom_log(POM_LOG_WARN "Item update hook failed for item %s", itm->name);
		}

	}

	val = itm->value;
	perf_item_unlock(itm);

	return val;
}

int perf_item_val_get_human(struct perf_item *itm, char *val, size_t size) {

	uint64_t value = perf_item_val_get_raw(itm);

	if (itm->type == perf_item_type_uptime) {
		int csec = value % 100;
		value /= 100;
		int secs = value % 60;
		value /= 60;
		int mins = value % 60;
		value /= 60;
		int hours = value % 24;
		value /= 24;
		if (value == 1) {
			return snprintf(val, size, "1 day, %02u:%02u:%02u.%02u", hours, mins, secs, csec);
		} else if (value > 1) {
			return snprintf(val, size, "%u days, %02u:%02u:%02u.%02u", (unsigned int)value, hours, mins, secs, csec);
		} else if (hours > 0) {
			return snprintf(val, size, "%02u:%02u:%02u.%02u", hours, mins, secs, csec);
		}

		return snprintf(val, size, "%02u:%02u.%02u", mins, secs, csec);

	}

	if (value > 99999) {
		value = (value + 500) / 1000;
		if (value > 9999) {
			value = (value + 500) / 1000;
			if (value > 9999) {
				value = (value + 500) / 1000;
				if (value > 9999) {
					value = (value + 500) / 1000;
					snprintf(val, size, "%llut", (long long unsigned int)value);
				} else {
					return snprintf(val, size, "%llug", (long long unsigned int)value);
				}
			} else {
				return snprintf(val, size, "%llum", (long long unsigned int)value);
			}
		} else {
			return snprintf(val, size, "%lluk", (long long unsigned int)value);
		}
	} else {
		return snprintf(val, size, "%llu", (long long unsigned int)value);
	}
	
	return 0;
}

int perf_item_val_get_human_1024(struct perf_item *itm, char *val, size_t size) {

	if (itm->type == perf_item_type_uptime)
		return 0; // Not applicable for uptime

	uint64_t value = perf_item_val_get_raw(itm);

	if (value > 99999) {
		value = (value + 512) / 1024;
		if (value > 9999) {
			value = (value + 512) / 1024;
			if (value > 9999) {
				value = (value + 512) / 1024;
				if (value > 9999) {
					value = (value + 512) / 1024;
					return snprintf(val, size, "%lluT", (long long unsigned int)value);
				} else {
					return snprintf(val, size, "%lluG", (long long unsigned int)value);
				}
			} else {
				return snprintf(val, size, "%lluM", (long long unsigned int)value);
			}
		} else {
			return snprintf(val, size, "%lluK", (long long unsigned int)value);
		}
	} else {
		return snprintf(val, size, "%llu", (long long unsigned int)value);
	}
	
	return 0;
}
