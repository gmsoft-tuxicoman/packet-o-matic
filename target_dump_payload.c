/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include "target_dump_payload.h"

#define PARAMS_NUM 1
char *target_dump_payload_params[PARAMS_NUM][3] = {
	{"prefix", "dump", "prefix of dumped files including directory"},
};

int target_register_dump_payload(struct target_reg *r) {

	copy_params(r->params_name, target_dump_payload_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_dump_payload_params, 2, PARAMS_NUM);

	r->init = target_init_dump_payload;
	r->process = target_process_dump_payload;
	r->close_connection = target_close_connection_dump_payload;
	r->cleanup = target_cleanup_dump_payload;


	return 1;

}

int target_cleanup_dump_payload(struct target *t) {

	clean_params(t->params_value, PARAMS_NUM);

	return 1;
}


int target_init_dump_payload(struct target *t) {

	copy_params(t->params_value, target_dump_payload_params, 1, PARAMS_NUM);

	return 1;
}


int target_process_dump_payload(struct target *t, struct rule_node *node, void *frame, unsigned int len) {

	struct target_conntrack_priv_dump_payload *cp;

	cp = (*t->conntrack_get_priv) (t, node, frame);

	unsigned int start = node_find_payload_start(node);
	unsigned int size = node_find_payload_size(node);


	if (!cp) {

		// Do not create a file is there is nothing to save
		if (size == 0)
			return 1;

		// New connection
		cp = malloc(sizeof(struct target_conntrack_priv_dump_payload));

		char filename[NAME_MAX];

		char outstr[20];
		bzero(outstr, 20);
		// YYYYMMDD-HHMMSS-UUUUUU
		char *format = "-%Y%m%d-%H%M%S-";
		struct timeval tv;
		struct tm *tmp;
		gettimeofday(&tv, NULL);
		tmp = localtime(&tv.tv_sec);
		strftime(outstr, 20, format, tmp);

		strcpy(filename, t->params_value[0]);
		strcat(filename, outstr);
		sprintf(outstr, "%u", (unsigned int)tv.tv_usec);
		strcat(filename, outstr);
		cp->fd = open(filename, O_RDWR | O_CREAT, 0666);

		if (cp->fd == -1) {
			free(cp);
			dprint("Unable to open file %s for writing : %s\n", filename, strerror(errno));
			return -1;
		}

		ndprint("%s opened\n", filename);

		(*t->conntrack_add_priv) (t, cp, node, frame);
	}
	
	write(cp->fd, frame + start, size);

	return 1;
};

int target_close_connection_dump_payload(void *conntrack_priv) {

	ndprint("Closing connection 0x%x\n", (unsigned) conntrack_priv);

	struct target_conntrack_priv_dump_payload *cp;
	cp = conntrack_priv;

	close(cp->fd);

	free(cp);

	return 1;

}



