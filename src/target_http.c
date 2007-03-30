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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "target_http.h"

#define MIME_TYPES_COUNT 25

char *mime_types[MIME_TYPES_COUNT][2] = {

	{ "private/unknown", "unk" }, // Special non-existant type
	{ "image/jpeg", "jpg" },
	{ "image/jpg", "jpg" },
	{ "image/gif", "gif" },
	{ "image/png", "png" },
	{ "image/bmp", "bmp" },
	{ "text/html", "html" },
	{ "application/x-javascript", "js" },
	{ "application/javascript", "js" },
	{ "text/x-js", "js" },
	{ "text/javascript", "js" },
	{ "application/zip", "gz" },
	{ "application/octet-stream", "bin" },
	{ "text/plain", "txt" },
	{ "message/rfc822", "msg" },
	{ "application/xml", "xml" },
	{ "text/xml", "xml" },
	{ "text/css", "css" },
	{ "image/x-icon", "ico" },
	{ "application/x-shockwave-flash", "swf" },
	{ "video/flv", "flv" },
	{ "video/mpeg", "mpg" },
	{ "application/x-rar-compressed", "rar" },
	{ "application/x-www-urlform-encoded", "url" },
	{ "text/calendar", "cal" },


};

unsigned char mime_types_hash[MIME_TYPES_COUNT];


#define PARAMS_NUM 1 
char *target_http_params[PARAMS_NUM][3] = {
	{"prefix", "dump", "prefix of dumped files including directory"},
};

struct target_functions *tg_functions;

unsigned int match_undefined_id;

int target_register_http(struct target_reg *r, struct target_functions *tg_funcs) {

	copy_params(r->params_name, target_http_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_http_params, 2, PARAMS_NUM);

	r->init = target_init_http;
	r->process = target_process_http;
	r->close_connection = target_close_connection_http;
	r->cleanup = target_cleanup_http;

	tg_functions = tg_funcs;

	match_undefined_id = (*tg_functions->match_register) ("undefined");

	// compute the stupidest hash ever
	bzero(mime_types_hash, MIME_TYPES_COUNT);
	int i, j;
	for (i = 0; i < MIME_TYPES_COUNT; i++) 
		for (j = 0; *(mime_types[i][0] + j); j++)
			mime_types_hash[i] += (unsigned char) *(mime_types[i][0] + j);
	return 1;

}

int target_cleanup_http(struct target *t) {

	clean_params(t->params_value, PARAMS_NUM);

	return 1;
}


int target_init_http(struct target *t) {

	copy_params(t->params_value, target_http_params, 1, PARAMS_NUM);

	return 1;
}


int target_process_http(struct target *t, struct layer *l, void *frame, unsigned int len, struct conntrack_entry *ce) {


	struct layer *lastl = l;
	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;


	struct target_conntrack_priv_http *cp;

	cp = (*tg_functions->conntrack_get_priv) (t, ce);

	if (!cp) { // We need to track all connections

		cp = malloc(sizeof(struct target_conntrack_priv_http));
		bzero(cp, sizeof(struct target_conntrack_priv_http));
		cp->state = HTTP_HEADER;
		cp->fd = -1;
		(*tg_functions->conntrack_add_priv) (t, cp, l, frame);
	
	}

	if (ce && cp->direction != CT_DIR_NONE && (ce->direction != cp->direction)) {
		dprint("Direction missmatch, %u, %u\n", ce->direction, cp->direction);
		return 1;
	}

	if (lastl->payload_size == 0) {
		ndprint("Payload size == 0\n");	
		return 1;
	}



	unsigned int pstart, psize;
	pstart = lastl->payload_start;
	psize = lastl->payload_size;

	if (cp->state == HTTP_HEADER) {
		char *pload = frame + lastl->payload_start;
		int i, lstart = 0;
		for (i = 0; i < lastl->payload_size; i++) {

			if (!pload[i] || (unsigned)pload[i] > 128) { // Non ascii char
				ndprint("NULL or non ASCII char in header packet\n");
				return 1;
			}

			if (pload[i] == '\n') {


				if (i - lstart >= 17 && !strncmp(pload + lstart, "Content-", 8)) { // We got a match
					lstart += 8;

					if (!strncmp(pload + lstart, "Type: ", 6)) {
						lstart += 6;
						while (pload[lstart] == ' ')
							lstart++;
						int j;
						for (j = 0;
							pload[lstart + j] != ' ' &&
							pload[lstart + j] != '\r' &&
							pload[lstart + j] != '\n' &&
							pload[lstart + j] != ';' && // we only want the first part of the mime-type
							j < i;
							j++);

						
						if (j > 255) {
							lstart = i + 1;
							continue;
						}



						char type[256];
						memcpy(type, pload + lstart, j);
						type[j] = 0;
						ndprint ("Mime type = %s\n", type);
						cp->state |= HTTP_HAVE_CTYPE;

						unsigned char hash = 0;
						int k;
						for (k = 0; k < j; k++)
							hash += (unsigned char) tolower(type[k]);
						
						for (k = 0; k < MIME_TYPES_COUNT; k++) {
							if (mime_types_hash[k] == hash && !strcasecmp(type, mime_types[k][0])) {
								cp->content_type = k;
								ndprint("Found content type %u (%s, %s)\n", k, type, mime_types[k][0]);
								break;
							}
						}

						if (k >= MIME_TYPES_COUNT) {
							dprint("Warning, unknown content type %s\n", type);
							cp->content_type = 0;
						}

					} else if (!strncmp(pload + lstart, "Length: ", 8)) {
						lstart += 8;
					
						while (pload[lstart] == ' ')
							lstart++;
						int j;
						for (j = 0;
							pload[lstart + j] != ' ' &&
							pload[lstart + j] != '\r' &&
							pload[lstart + j] != '\n' &&
							j < i;
							j++);

						
						char length[256];
						if (j > 255) {
							lstart = i + 1;
							continue;
						}
						memcpy(length, pload + lstart, j);
						length[j] = 0;
						if (sscanf(length, "%u", &cp->content_len) != 1) {
							lstart = i + 1;
							continue;
						}

						ndprint("Content length = %u\n", cp->content_len);
						cp->state |= HTTP_HAVE_CLEN;

					} else {
						lstart = i + 1;
						continue;
					}
					// One of the header matched

					if (!ce)
						cp->direction = CT_DIR_FWD;
					else if (ce->direction != CT_DIR_NONE)
						cp->direction = ce->direction;
					else if (ce->direction == CT_DIR_NONE)
						dprint("WTF ?!?\n");

				} else if (i - lstart == 1 && pload[lstart] == '\r') {
					pstart = i + 1 + lastl->payload_start;
					psize = (lastl->payload_size + lastl->payload_start) - pstart;
					ndprint("End of headers. %u bytes of payload\n", psize);
					break;

				}
		
				lstart = i + 1;
			}

		}

	}


	if (cp->content_len == 0) {
		cp->state = HTTP_HEADER;
		ndprint("Content len == 0\n");
		return 1;
	}

	// At this point the only possible state is HTTP_MATCH


	if (cp->fd == -1) {


		char filename[NAME_MAX];

		char outstr[20];
		bzero(outstr, 20);
		// YYYYMMDD-HHMMSS-UUUUUU
		char *format = "-%Y%m%d-%H%M%S-";
		struct timeval tv;
		struct tm *tmp;
		gettimeofday(&tv, NULL);
	        tmp = localtime((time_t*)&tv.tv_sec);

		strftime(outstr, 20, format, tmp);

		strcpy(filename, t->params_value[0]);
		strcat(filename, outstr);
		sprintf(outstr, "%u", (unsigned int)tv.tv_usec);
		strcat(filename, outstr);
		strcat(filename, ".");
		strcat(filename, mime_types[cp->content_type][1]);
		cp->fd = open(filename, O_RDWR | O_CREAT, 0666);

		if (cp->fd == -1) {
			free(cp);
			dprint("Unable to open file %s for writing : %s\n", filename, strerror(errno));
			return -1;
		}

		ndprint("%s opened\n", filename);

	}

	cp->pos += psize;

	write(cp->fd, frame + pstart, psize);
	ndprint("Saved %u of payload\n", psize);
	
	if (cp->pos >= cp->content_len) { // Everything was captuer, we can close the file
		cp->state = HTTP_HEADER;
		cp->content_len = 0;
		cp->content_type = 0;
		cp->pos = 0;
		close(cp->fd);
		cp->fd = -1;
	}

	return 1;
};

int target_close_connection_http(void *conntrack_priv) {

	ndprint("Closing connection 0x%lx\n", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_http *cp;
	cp = conntrack_priv;

	close(cp->fd);

	free(cp);

	return 1;

}



