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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "target_http.h"

#include "ptype_bool.h"
#include "ptype_string.h"

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


static const char *mime_types[MIME_TYPES_COUNT][3] = {

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

static unsigned char mime_types_hash[MIME_TYPES_COUNT];

static unsigned int match_undefined_id;
static struct target_mode *mode_default;

int target_register_http(struct target_reg *r) {

	r->init = target_init_http;
	r->open = target_open_http;
	r->process = target_process_http;
	r->close = target_close_http;
	r->cleanup = target_cleanup_http;

	match_undefined_id = match_register("undefined");

	// compute the stupidest hash ever
	memset(mime_types_hash, 0, MIME_TYPES_COUNT);
	int i, j;
	for (i = 0; i < MIME_TYPES_COUNT; i++) 
		for (j = 0; *(mime_types[i][0] + j); j++)
			mime_types_hash[i] += (unsigned char) *(mime_types[i][0] + j);

	mode_default = target_register_mode(r->type, "default", "Dump each HTTP connection's content into separate files");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "path", "/tmp", "Path of dumped files");
	target_register_param(mode_default, "dump_img", "no", "Dump the images or not");
	target_register_param(mode_default, "dump_vid", "no", "Dump the videos or not");
	target_register_param(mode_default, "dump_snd", "no", "Dump the images or not");
	target_register_param(mode_default, "dump_txt", "no", "Dump the text or not");
	target_register_param(mode_default, "dump_bin", "no", "Dump the binary or not");
	target_register_param(mode_default, "dump_doc", "no", "Dump the documents or not");


	return POM_OK;

}


static int target_init_http(struct target *t) {

	struct target_priv_http *priv = malloc(sizeof(struct target_priv_http));
	memset(priv, 0, sizeof(struct target_priv_http));

	t->target_priv = priv;

	priv->path = ptype_alloc("string", NULL);
	priv->dump_img = ptype_alloc("bool", NULL);
	priv->dump_vid = ptype_alloc("bool", NULL);
	priv->dump_snd = ptype_alloc("bool", NULL);
	priv->dump_txt = ptype_alloc("bool", NULL);
	priv->dump_bin = ptype_alloc("bool", NULL);
	priv->dump_doc = ptype_alloc("bool", NULL);

	if (!priv->path || !priv->dump_img || !priv->dump_vid || !priv->dump_snd || !priv->dump_txt || !priv->dump_bin || !priv->dump_doc) {
		target_cleanup_http(t);
		return POM_ERR;
	}
	
	target_register_param_value(t, mode_default, "path", priv->path);
	target_register_param_value(t, mode_default, "dump_img", priv->dump_img);
	target_register_param_value(t, mode_default, "dump_vid", priv->dump_vid);
	target_register_param_value(t, mode_default, "dump_snd", priv->dump_snd);
	target_register_param_value(t, mode_default, "dump_txt", priv->dump_txt);
	target_register_param_value(t, mode_default, "dump_bin", priv->dump_bin);
	target_register_param_value(t, mode_default, "dump_doc", priv->dump_doc);


	return POM_OK;
}

static int target_close_http(struct target *t) {

	struct target_priv_http *priv = t->target_priv;

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_http(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

static int target_cleanup_http(struct target *t) {

	struct target_priv_http *priv = t->target_priv;

	if (priv) {

		ptype_cleanup(priv->path);
		ptype_cleanup(priv->dump_img);
		ptype_cleanup(priv->dump_vid);
		ptype_cleanup(priv->dump_snd);
		ptype_cleanup(priv->dump_txt);
		ptype_cleanup(priv->dump_bin);
		ptype_cleanup(priv->dump_doc);
		free(priv);
	}

	return POM_OK;
}


static int target_open_http(struct target *t) {

	struct target_priv_http *priv = t->target_priv;

	if (PTYPE_BOOL_GETVAL(priv->dump_img)) // img
		priv->match_mask |= TYPE_IMG;
	if (PTYPE_BOOL_GETVAL(priv->dump_vid)) // vid
		priv->match_mask |= TYPE_VID;
	if (PTYPE_BOOL_GETVAL(priv->dump_snd)) // snd
		priv->match_mask |= TYPE_SND;
	if (PTYPE_BOOL_GETVAL(priv->dump_txt)) // txt
		priv->match_mask |= TYPE_TXT;
	if (PTYPE_BOOL_GETVAL(priv->dump_bin)) // bin
		priv->match_mask |= TYPE_BIN;
	if (PTYPE_BOOL_GETVAL(priv->dump_doc)) // doc
		priv->match_mask |= TYPE_DOC;

	return POM_OK;

}

static int target_process_http(struct target *t, struct frame *f) {

	struct target_priv_http *priv = t->target_priv;
	

	struct layer *lastl = f->l;
	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	if (!f->ce)
		if (conntrack_create_entry(f) == POM_ERR)
			return POM_OK;

	struct target_conntrack_priv_http *cp;

	cp = conntrack_get_target_priv(t, f->ce);

	if (!cp) { // We need to track all connections

		cp = malloc(sizeof(struct target_conntrack_priv_http));
		memset(cp, 0, sizeof(struct target_conntrack_priv_http));
		cp->state = HTTP_HEADER;
		cp->fd = -1;
		conntrack_add_target_priv(cp, t, f->ce, target_close_connection_http);

		cp->ce = f->ce;
		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;
	
	}

	if ((cp->state == HTTP_MATCH || cp->state == HTTP_NO_MATCH) && (f->ce->direction != cp->direction)) {
		return POM_OK;
	}

	if (lastl->payload_size == 0) {
		pom_log(POM_LOG_TSHOOT "Payload size == 0");	
		return POM_OK;
	}



	unsigned int pstart, psize;
	pstart = lastl->payload_start;
	psize = lastl->payload_size;

	if (cp->state == HTTP_HEADER) {
		char *pload = f->buff + lastl->payload_start;
		int i, lstart = 0;
		for (i = 0; i < lastl->payload_size; i++) {

			if (!pload[i] || (unsigned)pload[i] > 128) { // Non ascii char
				pom_log(POM_LOG_TSHOOT "NULL or non ASCII char in header packet");
				return POM_OK;
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
						pom_log(POM_LOG_TSHOOT "Mime type = %s", type);
						cp->state |= HTTP_HAVE_CTYPE;

						unsigned char hash = 0;
						int k;
						for (k = 0; k < j; k++)
							hash += (unsigned char) tolower(type[k]);
						
						for (k = 0; k < MIME_TYPES_COUNT; k++) {
							if (mime_types_hash[k] == hash && !strcasecmp(type, mime_types[k][0])) {
								cp->content_type = k;
								pom_log(POM_LOG_TSHOOT "Found content type %u (%s, %s)", k, type, mime_types[k][0]);
								break;
							}
						}

						if (k >= MIME_TYPES_COUNT) {
							pom_log(POM_LOG_TSHOOT "Warning, unknown content type %s", type);
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

						pom_log(POM_LOG_TSHOOT "Content length = %u", cp->content_len);
						cp->state |= HTTP_HAVE_CLEN;

					} else {
						lstart = i + 1;
						continue;
					}
					// One of the header matched

					cp->direction = f->ce->direction;

				} else if (i - lstart == 1 && pload[lstart] == '\r') {
					pstart = i + 1 + lastl->payload_start;
					psize = (lastl->payload_size + lastl->payload_start) - pstart;
					pom_log(POM_LOG_TSHOOT "End of headers. %u bytes of payload", psize);
					break;

				}
		
				lstart = i + 1;
			}

		}

	}

	if (cp->state == (HTTP_HAVE_CTYPE | HTTP_HAVE_CLEN | HTTP_HEADER)) {
		// Ok, we have all the info we need. Let's see if we need to actually save that
		if (*mime_types[cp->content_type][2] & priv->match_mask)
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
			strcpy(filename, PTYPE_STRING_GETVAL(priv->path));

			if (*(filename + strlen(filename) - 1) != '/')
				strcat(filename, "/");

			char outstr[20];
			memset(outstr, 0, sizeof(outstr));
			// YYYYMMDD-HHMMSS-UUUUUU
			char *format = "%Y%m%d-%H%M%S-";
			struct tm *tmp;
			tmp = localtime((time_t*)&f->tv.tv_sec);

			strftime(outstr, sizeof(outstr), format, tmp);

			strcat(filename, outstr);
			sprintf(outstr, "%u", (unsigned int)f->tv.tv_usec);
			strcat(filename, outstr);
			strcat(filename, ".");
			strcat(filename, mime_types[cp->content_type][1]);
			cp->fd = target_file_open(f->l, filename, O_RDWR | O_CREAT, 0666);

			if (cp->fd == -1) {
				char errbuff[256];
				strerror_r(errno, errbuff, sizeof(errbuff));
				pom_log(POM_LOG_ERR "Unable to open file %s for writing : %s", filename, errbuff);
				cp->state = HTTP_NO_MATCH;
				return POM_ERR;
			}

			pom_log(POM_LOG_TSHOOT "%s opened", filename);

		}


		cp->pos += psize;
		write(cp->fd, f->buff + pstart, psize);
		pom_log(POM_LOG_TSHOOT "Saved %u of payload", psize);
		

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
	return POM_OK;
};

static int target_close_connection_http(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_http *cp;
	cp = conntrack_priv;

	if (cp->fd != -1) {
		close(cp->fd);
	}

	struct target_priv_http *priv = t->target_priv;

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;


	free(cp);

	return POM_OK;

}



