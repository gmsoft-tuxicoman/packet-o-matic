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



#ifndef __PERF_H__
#define __PERF_H__


#define PERF_UPTIME_STOPPED (1LLU << 63)

enum perf_item_type {
	perf_item_type_counter = 0,
	perf_item_type_gauge,
	perf_item_type_uptime
};

struct perf_item {

	char *name;
	enum perf_item_type type;
	char *descr;
	uint64_t value;
	pthread_rwlock_t lock;
	struct perf_instance *instance;

	int (*update_hook) (struct perf_item *itm, void *priv);
	void *hook_priv;

	struct perf_item *prev, *next;

};

struct perf_instance {

	uint32_t id;
	void *object;
	pthread_rwlock_t lock;
	struct perf_item *items;
	struct perf_instance *prev, *next;

};

struct perf_class {

	char *name;
	struct perf_instance *instances;
	struct perf_class *next;

};

struct perf_class* perf_register_class(char *class_name);
struct perf_instance* perf_register_instance(struct perf_class *class, void *object);
struct perf_item* perf_add_item(struct perf_instance *instance, char *name, enum perf_item_type type, char *descr);
int perf_instance_lock(struct perf_instance *instance, int write);
int perf_instance_unlock(struct perf_instance *instance);
int perf_item_lock(struct perf_item *itm, int write);
int perf_item_unlock(struct perf_item *itm);
int perf_item_set_update_hook(struct perf_item *itm, int (*update_hook) (struct perf_item *itm, void *priv), void *priv);
int perf_remove_item(struct perf_instance *instance, struct perf_item *itm);
int perf_unregister_instance(struct perf_class *class, struct perf_instance *instance);
int perf_cleanup();

int perf_item_val_reset(struct perf_item *itm);
uint64_t perf_item_val_inc(struct perf_item *itm, uint64_t inc);
int perf_item_val_uptime_stop(struct perf_item *itm);
int perf_item_val_uptime_restart(struct perf_item *itm);
uint64_t perf_item_val_get_raw(struct perf_item *itm);
int perf_item_val_get_human(struct perf_item *itm, char *val, size_t size);
int perf_item_val_get_human_1024(struct perf_item *itm, char *val, size_t size);

#endif
