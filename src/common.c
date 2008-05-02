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
