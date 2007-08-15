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

#define MIME_TYPES_COUNT 45

#define MIME_BIN "\x01"
#define MIME_IMG "\x02"
#define MIME_VID "\x04"
#define MIME_SND "\x08"
#define MIME_TXT "\x10"
#define MIME_DOC "\x20"

#define TYPE_BIN 0x01
#define TYPE_IMG 0x02
#define TYPE_VID 0x04
#define TYPE_SND 0x08
#define TYPE_TXT 0x10
#define TYPE_DOC 0x20


const char *mime_types[MIME_TYPES_COUNT][3] = {

	{ "private/unknown", "unk", MIME_BIN }, // Special non-existant type
	{ "application/x-javascript", "js", MIME_TXT },
	{ "application/javascript", "js", MIME_TXT },
	{ "application/json", "json", MIME_TXT },
	{ "application/x-json", "json", MIME_TXT },
	{ "application/zip", "gz", MIME_BIN },
	{ "application/octet-stream", "bin", MIME_BIN },
	{ "application/octetstream", "bin", MIME_BIN },
	{ "application/x-shockwave-flash", "swf", MIME_BIN },
	{ "application/x-rar-compressed", "rar", MIME_BIN },
	{ "application/x-www-urlform-encoded", "url", MIME_TXT },
	{ "application/xml", "xml", MIME_TXT },
	{ "application/pdf", "pdf", MIME_DOC },
	{ "application/vnd.ms-excel", "xls", MIME_DOC },
	{ "application/vnd.ms-powerpoint", "ppt", MIME_DOC },
	{ "application/msword", "doc", MIME_DOC },
	{ "audio/mpeg", "mp3", MIME_SND },
	{ "audio/mp3", "mp3", MIME_SND },
	{ "audio/x-pn-realaudio", "rm", MIME_SND },
	{ "video/x-ms-wma", "wma", MIME_SND },
	{ "audio/x-wav", "wav", MIME_SND },
	{ "audio/wav", "wav", MIME_SND },
	{ "image/jpeg", "jpg", MIME_IMG },
	{ "image/pjpeg", "pjpg", MIME_IMG },
	{ "image/jpg", "jpg", MIME_IMG },
	{ "image/gif", "gif", MIME_IMG },
	{ "image/png", "png", MIME_IMG },
	{ "image/bmp", "bmp", MIME_IMG },
	{ "image/x-icon", "ico", MIME_IMG },
	{ "message/rfc822", "msg", MIME_TXT },
	{ "text/html", "html", MIME_TXT },
	{ "text/x-js", "js", MIME_TXT },
	{ "text/javascript", "js", MIME_TXT },
	{ "text/plain", "txt", MIME_TXT },
	{ "text/xml", "xml", MIME_TXT },
	{ "text/css", "css", MIME_TXT },
	{ "text/calendar", "cal", MIME_TXT },
	{ "video/flv", "flv", MIME_VID },
	{ "video/x-flv", "flv", MIME_VID },
	{ "video/quicktime", "mov", MIME_VID },
	{ "video/mpeg", "mpg", MIME_VID },
	{ "video/x-ms-asf", "asf", MIME_VID },
	{ "video/x-msvideo", "avi", MIME_VID },
	{ "video/vnd.divx", "avi", MIME_VID },
	{ "video/x-ms-wmv", "wmv", MIME_VID },


};

unsigned char mime_types_hash[MIME_TYPES_COUNT];


#define PARAMS_NUM 7
char *target_http_params[PARAMS_NUM][3] = {
	{"path", ".", "path to the directory where the dumped files will be saved"},
	{"dump_img", "0", "specifiy if you want to dump image content or not"},
	{"dump_vid", "0", "specifiy if you want to dump video content or not"},
	{"dump_snd", "0", "specifiy if you want to dump audio content or not"},
	{"dump_txt", "0", "specifiy if you want to dump text content or not"},
	{"dump_bin", "0", "specifiy if you want to dump binary content or not"},
	{"dump_doc", "0", "specifiy if you want to dump documents content or not"},
	
};

struct target_functions *tg_functions;

unsigned int match_undefined_id;

int target_register_http(struct target_reg *r, struct target_functions *tg_funcs) {

	copy_params(r->params_name, target_http_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_http_params, 2, PARAMS_NUM);

	r->init = target_init_http;
	r->open = target_open_http;
	r->process = target_process_http;
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
	if (t->target_priv)
		free(t->target_priv);

	return 1;
}


int target_init_http(struct target *t) {

	copy_params(t->params_value, target_http_params, 1, PARAMS_NUM);

	t->target_priv = malloc(sizeof(int));
	int *match_mask = t->target_priv;
	*match_mask = 0;

	return 1;
}


int target_open_http(struct target *t) {

	int *match_mask = t->target_priv;

	if (*t->params_value[1] == '1') // img
		*match_mask |= TYPE_IMG;
	if (*t->params_value[2] == '1') // vid
		*match_mask |= TYPE_VID;
	if (*t->params_value[3] == '1') // snd
		*match_mask |= TYPE_SND;
	if (*t->params_value[4] == '1') // txt
		*match_mask |= TYPE_TXT;
	if (*t->params_value[5] == '1') // bin
		*match_mask |= TYPE_BIN;
	if (*t->params_value[6] == '1') // doc
		*match_mask |= TYPE_DOC;

	return 1;

}

int target_process_http(struct target *t, struct frame *f) {


	struct layer *lastl = f->l;
	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	if (!f->ce)
		(*tg_functions->conntrack_create_entry) (f);

	struct target_conntrack_priv_http *cp;

	cp = (*tg_functions->conntrack_get_priv) (t, f->ce);

	if (!cp) { // We need to track all connections

		cp = malloc(sizeof(struct target_conntrack_priv_http));
		bzero(cp, sizeof(struct target_conntrack_priv_http));
		cp->state = HTTP_HEADER;
		cp->fd = -1;
		(*tg_functions->conntrack_add_priv) (cp, t, f->ce, target_close_connection_http);
	
	}

	if ((cp->state == HTTP_MATCH || cp->state == HTTP_NO_MATCH)&& cp->direction != CT_DIR_ONEWAY && (f->ce->direction != cp->direction)) {
		//dprint("Direction missmatch, %u, %u\n", f->ce->direction, cp->direction);
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
		char *pload = f->buff + lastl->payload_start;
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

					if (f->ce->direction != CT_DIR_ONEWAY)
						cp->direction = f->ce->direction;
					else if (f->ce->direction == CT_DIR_ONEWAY)
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

	if (cp->state == (HTTP_HAVE_CTYPE | HTTP_HAVE_CLEN | HTTP_HEADER)) {
		// Ok, we have all the info we need. Let's see if we need to actually save that
		int *match_mask = t->target_priv;
		if (*mime_types[cp->content_type][2] & *match_mask)
			cp->state = HTTP_MATCH;
		else
			cp->state = HTTP_NO_MATCH;
	} else if (cp->state == (HTTP_HAVE_CLEN | HTTP_HEADER)) {
		cp->state = HTTP_NO_MATCH;
	} else if (cp->state & HTTP_HEADER)
		cp->state = HTTP_HEADER;


	if (cp->state == HTTP_MATCH) {

		if (cp->fd == -1) {

			char filename[NAME_MAX];
			strcpy(filename, t->params_value[0]);

			if (filename[strlen(filename) - 1] != '/')
				strcat(filename, "/");

			// Check if the directory exists yet
			if (lastl->prev) {
				struct layer_info *inf = lastl->prev->infos;
				while (inf) {
					if (!strcmp(inf->name, "src")) {
						(*tg_functions->layer_info_snprintf) (filename + strlen(filename), NAME_MAX - strlen(filename), inf);
						strcat(filename, "/");
					}
					inf = inf->next;
				}

				struct stat sbuf;
				if (stat(filename, &sbuf) == -1) {
					if (mkdir(filename, 0777) == -1) {
						dprint("error while creating directory %s\n", filename);
						return -1;
					}
				}

			}
			

			char outstr[20];
			bzero(outstr, 20);
			// YYYYMMDD-HHMMSS-UUUUUU
			char *format = "%Y%m%d-%H%M%S-";
			struct tm *tmp;
			tmp = localtime((time_t*)&f->tv.tv_sec);

			strftime(outstr, 20, format, tmp);

			strcat(filename, outstr);
			sprintf(outstr, "%u", (unsigned int)f->tv.tv_usec);
			strcat(filename, outstr);
			strcat(filename, ".");
			strcat(filename, mime_types[cp->content_type][1]);
			cp->fd = open(filename, O_RDWR | O_CREAT, 0666);

			if (cp->fd == -1) {
				char errbuff[256];
				strerror_r(errno, errbuff, 256);
				dprint("Unable to open file %s for writing : %s\n", filename, errbuff);
				cp->state = HTTP_NO_MATCH;
				return -1;
			}

			ndprint("%s opened\n", filename);

		}


		cp->pos += psize;
		write(cp->fd, f->buff + pstart, psize);
		ndprint("Saved %u of payload\n", psize);
		

	} 

	if (cp->state == HTTP_MATCH || cp->state == HTTP_NO_MATCH) {
		if (cp->pos >= cp->content_len) { // Everything was captured, we can close the file
			cp->state = HTTP_HEADER;
			cp->content_len = 0;
			cp->content_type = 0;
			cp->pos = 0;
			if (cp->fd != -1) {
				close(cp->fd);
			}
			cp->fd = -1;
		}
	}
	return 1;
};

int target_close_connection_http(struct conntrack_entry *ce, void *conntrack_priv) {

	ndprint("Closing connection 0x%lx\n", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_http *cp;
	cp = conntrack_priv;

	if (cp->fd != -1) {
		close(cp->fd);
	}

	free(cp);

	return 1;

}



