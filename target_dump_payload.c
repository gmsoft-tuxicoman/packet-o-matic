
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include "target_dump_payload.h"


int target_register_dump_payload(struct target_reg *r) {

	r->init = target_init_dump_payload;
	r->open = target_open_dump_payload;
	r->process = target_process_dump_payload;
	r->close_connection = target_close_connection_dump_payload;
	r->close = target_close_dump_payload;
	r->cleanup = target_cleanup_dump_payload;


	return 1;

}

int target_cleanup_dump_payload(struct target *t) {

	if (t->target_priv)
		free(t->target_priv);

	return 1;
}


int target_init_dump_payload(struct target *t) {


	struct target_priv_dump_payload *priv = malloc(sizeof(struct target_priv_dump_payload));
	bzero(priv, sizeof(struct target_priv_dump_payload));

	t->target_priv = priv;
	

	return 1;
}


int target_open_dump_payload(struct target *t, const char *prefix) {

	struct target_priv_dump_payload *priv = t->target_priv;
	strncpy(priv->prefix, prefix, NAME_MAX);

	return 1;	
}


int target_process_dump_payload(struct target *t, struct rule_node *node, void *frame, unsigned int len) {

	struct target_priv_dump_payload *priv = t->target_priv;
	struct target_conntrack_priv_dump_payload *cp;

	cp = (*t->conntrack_get_priv) (t, node, frame);

	unsigned int start = node_find_payload_start(node);


	if (!cp) {

		// Do not create a file is there is nothing to save
		if (start >= len)
			return 1;

		// New connection
		cp = malloc(sizeof(struct target_conntrack_priv_dump_payload));

		char filename[NAME_MAX];

		char outstr[20];
		bzero(outstr, 20);
		// YYYYMMDD-HHMMSS-UUUUUU
		char *format = "%Y%m%d-%H%M%S-";
		struct timeval tv;
		struct tm *tmp;
		gettimeofday(&tv, NULL);
		tmp = localtime(&tv.tv_sec);
		strftime(outstr, 20, format, tmp);

		strcpy(filename, priv->prefix);
		strcat(filename, outstr);
		sprintf(outstr, "%u", (unsigned int)tv.tv_usec);
		strcat(filename, outstr);
		cp->fd = open(filename, O_RDWR | O_CREAT, 0666);

		if (cp->fd == -1) {
			free(cp);
			dprint("Unable to open file %s for writing\n", filename);
			return -1;
		}

		ndprint("%s opened\n", filename);

		(*t->conntrack_add_priv) (t, cp, node, frame);
	}

	write(cp->fd, frame + start, len - start);

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

int target_close_dump_payload(struct target *t) {
	
	return 1;
};



