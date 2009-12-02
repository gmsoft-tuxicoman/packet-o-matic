/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2009 Guy Martin <gmsoft@tuxicoman.be>
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
	
	tmp->object = object;

	tmp->next = class->instances;
	if (tmp->next)
		tmp->next->prev = tmp;

	class->instances = tmp;

	return tmp;

}

struct perf_item *perf_add_item(struct perf_instance *instance, char *name, enum perf_item_type type, char *descr) {

	struct perf_item *tmp = instance->items, *tmp_last = NULL;
	while (tmp) {
		if (!strcmp(tmp->name, name)) {
			pom_log(POM_LOG_WARN "Item %s already added to instance", name);
			return NULL;
		}
		tmp_last = tmp;
		tmp = tmp->next;
	}

	tmp = malloc(sizeof(struct perf_item));
	memset(tmp, 0, sizeof(struct perf_item));
	tmp->name = strdup(name);
	tmp->type = type;
	tmp->descr = strdup(descr);
	if (type == perf_item_type_uptime)
		tmp->value = PERF_UPTIME_STOPPED;

	if (!tmp_last) {
		instance->items = tmp;
	} else {
		tmp_last->next = tmp;
		tmp->prev = tmp_last;
	}
	
	return tmp;

}

int perf_item_set_update_hook(struct perf_item *itm, int (*update_hook) (struct perf_item *itm, void *priv), void *priv) {

	itm->update_hook = update_hook;
	itm->hook_priv = priv;
	return POM_OK;
}

int perf_remove_item(struct perf_instance *instance, struct perf_item *itm) {

	if (!itm->prev) {
		instance->items = itm;
	} else {
		itm->prev->next = itm->next;
	}

	if (itm->next)
		itm->next->prev = itm->prev;

	free(itm->name);
	free(itm->descr);
	free(itm);

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

	struct perf_item *itm = tmp->items;
	while (itm) {
		struct perf_item *del_item = itm;
		itm = itm->next;
		free(del_item->name);
		free(del_item->descr);
		free(del_item);
	}

	if (!tmp->prev)
		class->instances = tmp->next;
	else
		tmp->prev->next = tmp->next;

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	free(tmp);


	return POM_OK;
}

int perf_cleanup() {
	
	while (perfs_head) {
		struct perf_class *tmp = perfs_head;
		perfs_head = perfs_head->next;
		free(tmp->name);
		if (tmp->instances)
			pom_log(POM_LOG_WARN "Warning not all instances from perf_class were unregistered");
		free(tmp);
	}

	return POM_OK;
}


int perf_item_val_reset(struct perf_item *itm) {

	if (itm->type == perf_item_type_uptime) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		// Time is stored in centisecs
		itm->value = (tv.tv_sec * 100) + (tv.tv_usec / 10000);
	} else if (itm->update_hook) {
		pom_log(POM_LOG_WARN "Cannot reset item value when an update hook is set");
		return POM_ERR;
	} else {
		itm->value = 0;
	}
	return POM_OK;
}

uint64_t perf_item_val_inc(struct perf_item *itm, uint64_t inc) {

	if (itm->type == perf_item_type_uptime) {
		pom_log(POM_LOG_WARN "Cannot increment item of type uptime");
	} else if (itm->update_hook) {
		pom_log(POM_LOG_WARN "Cannot increment item when it has an update hook");
	} else {
		itm->value += inc;
	}
	return itm->value;
}

int perf_item_val_uptime_stop(struct perf_item *itm) {

	if (itm->type != perf_item_type_uptime) {
		pom_log(POM_LOG_WARN "Warning, trying to stop uptime on a non uptime performance item");
		return POM_ERR;
	}

	if (itm->value & PERF_UPTIME_STOPPED) {
		pom_log(POM_LOG_WARN "Warning, uptime already stopped");
		return POM_ERR;
	}

	itm->value = perf_item_val_get_raw(itm) | PERF_UPTIME_STOPPED;

	return POM_OK;

}

uint64_t perf_item_val_get_raw(struct perf_item *itm) {

	if (itm->type == perf_item_type_uptime) {

		// Return raw value if uptime count was stopped
		if (itm->value & PERF_UPTIME_STOPPED)
			return itm->value & ~PERF_UPTIME_STOPPED;

		struct timeval tv;
		gettimeofday(&tv, NULL);
		uint64_t now = (tv.tv_sec * 100) + (tv.tv_usec / 10000);
		return now - itm->value;
	}

	if (itm->update_hook)
		if (itm->update_hook(itm, itm->hook_priv) == POM_ERR) {
			pom_log(POM_LOG_WARN "Item update hook failed for item %s", itm->name);
		}

	return itm->value;
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
					snprintf(val, size, "%llut", value);
				} else {
					return snprintf(val, size, "%llug", value);
				}
			} else {
				return snprintf(val, size, "%llum", value);
			}
		} else {
			return snprintf(val, size, "%lluk", value);
		}
	} else {
		return snprintf(val, size, "%llu", value);
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
					return snprintf(val, size, "%lluT", value);
				} else {
					return snprintf(val, size, "%lluG", value);
				}
			} else {
				return snprintf(val, size, "%lluM", value);
			}
		} else {
			return snprintf(val, size, "%lluK", value);
		}
	} else {
		return snprintf(val, size, "%llu", value);
	}
	
	return 0;
}
