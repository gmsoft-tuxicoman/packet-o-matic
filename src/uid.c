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

#include "uid.h"

static uint32_t *uid_table = NULL;
static uint32_t uid_table_size = 0;
static unsigned int uid_random_seed;
pthread_mutex_t uid_table_lock;

int uid_init() {
	
	uid_random_seed = (unsigned int) time(NULL) + (unsigned int) pthread_self();
	srand(uid_random_seed);

	if (pthread_mutex_init(&uid_table_lock, NULL))
		return POM_ERR;
	
	return POM_OK;
}

int uid_check(uint32_t uid) {

	if (!uid) // 0 is not allowed
		return POM_ERR;

	uint32_t i;

	for (i = 0; i < uid_table_size; i++) {
		if (uid_table[i] == uid)
			return POM_ERR;
	}

	return POM_OK;
}

uint32_t uid_get_new() {

	uint32_t new_uid;

	uid_lock();

	do {
		new_uid = rand_r(&uid_random_seed);
	} while (uid_check(new_uid) == POM_ERR);

	uid_table_size++;
	uid_table = realloc(uid_table, sizeof(uint32_t) * uid_table_size);
	uid_table[uid_table_size - 1] = new_uid;

	uid_unlock();

	return new_uid;

}

uint32_t uid_set(uint32_t uid) {

	uid_lock();

	while (uid_check(uid) == POM_ERR) {
		uid = rand_r(&uid_random_seed);
	}

	uid_table_size++;
	uid_table = realloc(uid_table, sizeof(uint32_t) * uid_table_size);
	uid_table[uid_table_size - 1] = uid;

	uid_unlock();

	return uid;

}

int uid_release(uint32_t uid) {

	uint32_t i = 0;

	uid_lock();

	for (i = 0; i < uid_table_size; i++) {
		if (uid_table[i] == uid)
			break;
	}

	if (i > uid_table_size) {
		pom_log(POM_LOG_WARN "UID %u not found when releasing it", uid);
		uid_unlock();
		return POM_ERR;
	}

	uid_table_size--;
	memmove(&uid_table[i], &uid_table[i + 1], sizeof(uint32_t) * (uid_table_size - i));

	uid_table = realloc(uid_table, sizeof(uint32_t) * uid_table_size);

	uid_unlock();

	return POM_OK;

}

int uid_lock() {

	if (pthread_mutex_lock(&uid_table_lock)) {
		pom_log(POM_LOG_ERR "Error while locking the uid lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;
}

int uid_unlock() {

	if (pthread_mutex_unlock(&uid_table_lock)) {
		pom_log(POM_LOG_ERR "Error while locking the uid lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;
}

int uid_cleanup() {

	if (uid_table)
		free(uid_table);
	
	uid_table_size = 0;

	pthread_mutex_destroy(&uid_table_lock);

	return POM_OK;

}
