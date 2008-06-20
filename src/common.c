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

static unsigned int random_seed;

void pom_log(const char *format, ...) {

	int level = *POM_LOG_INFO;

	if (format[0] <= *POM_LOG_TSHOOT) {
		level = format[0];
		format++;
	}

	va_list arg_list;

	if (level > debug_level)
		return;

	if (console_output) {
		va_start(arg_list, format);
		vprintf(format, arg_list);
		va_end(arg_list);
	}

	va_start(arg_list, format);
	mgmtsrv_send_debug(format, arg_list);
	va_end(arg_list);


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
		
		pom_log(POM_LOG_TSHOOT "Unable to load %s : %s\r\n", libname, dlerror());

		memset(buff, 0, NAME_MAX);
		strcat(buff, LIBDIR);
		strcat(buff, "/");
		strcat(buff, libname);
		*handle = dlopen(buff, RTLD_FLAGS);
	}

	if (!*handle) {
		pom_log(POM_LOG_TSHOOT "Unable to load %s : %s\r\n", buff, dlerror());
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
	struct input_caps ic;
	if (input_getcaps(f->input, &ic) == POM_ERR) {	
		pom_log(POM_LOG_ERR "Error while trying to get input caps\r\n");
		return POM_ERR;
	}

	int total_len = length + ic.buff_align_offset + 4;
	f->buff_base = malloc(total_len);
	f->buff = (void*) (((long)f->buff_base & ~3) + 4 + ic.buff_align_offset);
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

	if (!path) {
		res = list_modules_browse(LIBDIR, type);
	} else {
		char *my_path = malloc(strlen(path) + 1);
		strcpy(my_path, path);

		char *str, *token, *saveptr = NULL;
		for (str = my_path; ; str = NULL) {
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


		free(my_path);
	}
	

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

