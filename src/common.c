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



#include "common.h"
#include "mgmtsrv.h"
#include "input.h"

#include <dirent.h>
#include <pthread.h>

int console_output;
unsigned int console_debug_level;
static unsigned int random_seed;

static struct log_entry *log_head = NULL, *log_tail = NULL;
static unsigned int log_buffer_size = 0;
static pthread_rwlock_t log_buffer_lock = PTHREAD_RWLOCK_INITIALIZER;
static uint32_t log_buffer_entry_id = 0;

void pom_log_internal(char *file, const char *format, ...) {

	int level = *POM_LOG_INFO;

	if (format[0] <= *POM_LOG_TSHOOT) {
		level = format[0];
		format++;
	}


	va_list arg_list;

	char buff[2048];
	va_start(arg_list, format);
	vsnprintf(buff, sizeof(buff) - 1, format, arg_list);
	va_end(arg_list);


	struct log_entry *entry = malloc(sizeof(struct log_entry));


	memset(entry, 0, sizeof(struct log_entry));

	char *dot = strchr(file, '.');
	unsigned int len = strlen(file);
	if (dot) {
		unsigned int new_len = dot - file;
		if (new_len < len)
			len = new_len;
	}

	entry->file = malloc(len + 1);
	memset(entry->file, 0, len + 1);
	strncat(entry->file, file, len);
	
	entry->data = malloc(strlen(buff) + 1);
	strcpy(entry->data, buff);
	
	entry->level = level;
	if (level < *POM_LOG_TSHOOT) {
		entry->id = log_buffer_entry_id;
		log_buffer_entry_id++;
	}

	mgmtsrv_send_debug(entry);

	if (console_output && console_debug_level >= level)
		printf("%s: %s\n", entry->file, entry->data);

	if (level >= *POM_LOG_TSHOOT) { // We don't want to save troubleshooting output
		free(entry->file);
		free(entry->data);
		free(entry);
		return;
	}


	int result = pthread_rwlock_wrlock(&log_buffer_lock);

	if (result) {
		printf("Error while locking the log lock. Aborting.\r");
		abort();
		return; // never reached
	}

	if (!log_tail) {
		log_head = entry;
		log_tail = entry;
	} else {
		entry->prev = log_tail;
		log_tail->next = entry;
		log_tail = entry;
	}
	log_buffer_size++;

	while (log_buffer_size > POM_LOG_BUFFER_SIZE) {
		struct log_entry *tmp = log_head;
		log_head = log_head->next;
		log_head->prev = NULL;

		free(tmp->file);
		free(tmp->data);
		free(tmp);
		
		log_buffer_size--;
	}


	if (pthread_rwlock_unlock(&log_buffer_lock)) {
		printf("Error while unlocking the log lock. Aborting.\r");
		abort();
		return; // never reached
	}

}

struct log_entry *pom_log_get_head() {

	return log_head;
}

struct log_entry *pom_log_get_tail() {

	return log_tail;
}

uint32_t pom_log_get_serial() {

	return log_buffer_entry_id;
}

int pom_log_rlock() {

	if (pthread_rwlock_rdlock(&log_buffer_lock)) {
		pom_log(POM_LOG_ERR "Error while locking the log lock. Aborting");
		abort();
		return POM_ERR;
	}
	return POM_OK;
}

int pom_log_unlock() {

	
	if (pthread_rwlock_unlock(&log_buffer_lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the log lock. Aborting");
		abort();
		return POM_ERR;
	}

	return POM_OK;
}

int pom_log_cleanup() {

	while (log_head) {
		struct log_entry *tmp = log_head;
		log_head = log_head->next;
		free(tmp->file);
		free(tmp->data);
		free(tmp);

	}
	
	log_tail = NULL;

	return POM_OK;
}

void *lib_get_register_func(const char *type, const char *name, void **handle) {

	char libname[NAME_MAX];
	memset(libname, 0, NAME_MAX);

	strcat(libname, type);
	strcat(libname, "_");
	strcat(libname, name);
	strcat(libname, ".so");

	// First try to open with automatic resolving for LD_LIBRARY_PATH
	*handle = dlopen(libname, RTLD_FLAGS);

	char buff[NAME_MAX];

	// Fallback on hardcoded LIBDIR
	if (!*handle) {
		
		pom_log(POM_LOG_TSHOOT "Unable to load %s : %s", libname, dlerror());

		memset(buff, 0, NAME_MAX);
		strcat(buff, LIBDIR);
		strcat(buff, "/");
		strcat(buff, libname);
		*handle = dlopen(buff, RTLD_FLAGS);
	}

	if (!*handle) {
		pom_log(POM_LOG_TSHOOT "Unable to load %s : %s", buff, dlerror());
		return NULL;
	}
	dlerror();

	memset(buff, 0, NAME_MAX);
	strcat(buff, type);
	strcat(buff, "_register_");
	strcat(buff, name);
	
	return dlsym(*handle, buff);

}

// takes care of allocating f->buff_base and set correctly f->buff and f->bufflen

int frame_alloc_aligned_buff(struct frame *f, int length) {

	int total_len = length + f->align_offset + 4;
	f->buff_base = malloc(total_len);
	f->buff = (void*) (((long)f->buff_base & ~3) + 4 + f->align_offset);
	f->bufflen = total_len - ((long)f->buff - (long)f->buff_base);

	return POM_OK;

}

static char ** list_modules_browse(char *path, char *type) {


	DIR *d;
	d = opendir(path);
	if (!d) 
		return 0;

	struct dirent *dp;
	char name[NAME_MAX];

	char *scanstr = malloc(strlen(type) + 4);
	strcpy(scanstr, type);
	strcat(scanstr, "_%s");


	char **res = malloc(sizeof(char *));
	*res = 0;
	int size = 0;

	while ((dp = readdir(d))) {

		if (sscanf(dp->d_name, scanstr, name) == 1) {
			char *dot = strchr(name, '.');
			*dot = 0;
			size++;
			res = realloc(res, sizeof(char *) * (size + 1));
			res[size] = NULL;
			res[size - 1] = malloc(strlen(name) + 1);
			strcpy(res[size - 1], name);
		}
	}

	closedir(d);
	free(scanstr);

	return res;

}

char ** list_modules(char *type) {


	char ** res = malloc(sizeof(char *));
	*res = 0;
	int size = 0;

	char *path = getenv("LD_LIBRARY_PATH");
	if (!path) 
		path = LIBDIR;

	char *mypath = malloc(strlen(path) + 1);
	strcpy(mypath, path);

	char *str, *token, *saveptr = NULL;
	for (str = mypath; ; str = NULL) {
		token = strtok_r(str, ":", &saveptr);
		if (!token)
			break;

		int i, dupe = 0;
		char **list;
		list = list_modules_browse(token, type);
		for (i = 0; list[i]; i++) {
			int j;
			for (j = 0; res[j]; j++) {
				if (!strcmp(res[j], list[i])) {
					dupe = 1;
					break;
				}
			}
			if (!dupe) {
				size++;
				res = realloc(res, sizeof(char *) * (size + 1));
				res[size] = NULL;
				res[size - 1] = malloc(strlen(list[i]) + 1);
				strcpy(res[size - 1],list[i]);
			}

			dupe = 0;

		}

		for (i = 0; list[i]; i++)
			free(list[i]);
		free(list);
	}

	free(mypath);

	return res;
}


int uid_init() {

	random_seed = (unsigned int) time(NULL) + (unsigned int) pthread_self();
	srand(random_seed);

	return POM_OK;
}

uint32_t get_uid() {

	return (uint32_t) rand_r(&random_seed);
}

int layer_find_start(struct layer *l, int header_type) {
	
	if (!l)
		return POM_ERR;

	do {
		if(l->type == header_type) {
			if (l->prev)
				return l->prev->payload_start;
			else
				return 0;
		}
		l = l->next;
	} while(l);

	return POM_ERR;
}

int base64_decode(char *output, char *input) {

	if (strlen(input) % 4) {
		pom_log(POM_LOG_WARN "Base64 input length not multiple of 4");
		return POM_ERR;
	}

	char *block, value[4];
	
	int len = POM_ERR;

	block = input;
	while (block[0]) {
		int i;
		for (i = 0; i < 4; i++) {
			if (block[i] >= 'A' && block[i] <= 'Z') {
				value[i] = block[i] - 'A';
			} else if (block[i] >= 'a' && block[i] <= 'z') {
				value[i] = block[i] - 'a' + 26;
			} else if (block[i] >= '0' && block[i] <= '9') {
				value[i] = block[i] - '0' + 52;
			} else if (block[i] == '+') {
				value[i] = 62;
			} else if (block[i] == '/') {
				value[i] = 63;
			} else if (block[i] == '=') {
				value[i] = 0;
			}
		}
			
		if (block[1] == '=')
			return len;
		output[0] = ((value[0] << 2) | (0x3 & (value[1] >> 4)));
		len++;

		if (block[2] == '=')
			return len;
		output[1] = ((value[1] << 4) | (0xf & (value[2] >> 2)));
		len++;

		if (block[3] == '=')
			return len;
		output[2] = ((value[2] << 6) | value[3]);
		len++;

		output += 3;
		block += 4;

	}

	return len;

}


uint64_t bswap64(uint64_t x) {

#ifdef _LP64
	/*
	 * Assume we have wide enough registers to do it without touching
	 * memory.
	 */
	return  ( (x << 56) & 0xff00000000000000UL ) |
		( (x << 40) & 0x00ff000000000000UL ) |
		( (x << 24) & 0x0000ff0000000000UL ) |
		( (x <<  8) & 0x000000ff00000000UL ) |
		( (x >>  8) & 0x00000000ff000000UL ) |
		( (x >> 24) & 0x0000000000ff0000UL ) |
		( (x >> 40) & 0x000000000000ff00UL ) |
		( (x >> 56) & 0x00000000000000ffUL );
#else
	/*
	 * Split the operation in two 32bit steps.
	 */
	uint32_t tl, th;

	th = ntohl((uint32_t)(x & 0x00000000ffffffffULL));
	tl = ntohl((uint32_t)((x >> 32) & 0x00000000ffffffffULL));
	return ((uint64_t)th << 32) | tl;
#endif

}


