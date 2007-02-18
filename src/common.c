/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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


#ifdef DEBUG

void dprint_hex(unsigned char *str, unsigned int len) {

	int i;
	
	for (i = 0; i < len; i++)
		printf("%02X ", *(str + i));
}

#endif


void *lib_get_register_func(const char *type, const char *name, void **handle) {

	char libname[NAME_MAX];
	bzero(libname, NAME_MAX);

	strcat(libname, type);
	strcat(libname, "_");
	strcat(libname, name);
	strcat(libname, ".so");

	// First try to open with automatic resolving for LD_LIBRARY_PATH
	*handle = dlopen(libname, RTLD_NOW);

	char buff[NAME_MAX];

	// Fallback on hardcoded LIBDIR
	if (!*handle) {
		
		dlerror();

		bzero(buff, NAME_MAX);
		strcat(buff, LIBDIR);
		strcat(buff, "/");
		strcat(buff, libname);
		*handle = dlopen(buff, RTLD_NOW);
	}

	if (!*handle) {
/*		dprint("Unable to load %s %s : ", type, name);
		dprint(dlerror());
		dprint("\n");*/
		return NULL;
	}
	dlerror();

	bzero(buff, NAME_MAX);
	strcat(buff, type);
	strcat(buff, "_register_");
	strcat(buff, name);
	
	return dlsym(*handle, buff);

}
