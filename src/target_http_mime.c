/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#include "target_http.h"
#include "target_http_mime.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <ctype.h>

#include "ptype_string.h"

#define HTTP_MIME_TYPE_HASH_INITVAL 0x2f67bd9a // random value
#define HTTP_MIME_TYPE_HASH_SIZE_RATIO 4

struct mime_type_entry *mime_types_db = NULL;
unsigned int mime_type_db_size = 0;

int target_http_mime_types_read_db(struct target_priv_http *priv) {

	int fd = open(PTYPE_STRING_GETVAL(priv->mime_types_db), O_RDONLY);
	if (fd == -1)
		return POM_ERR;

	struct stat s;
	if (fstat(fd, &s) == -1) {
		close(fd);
		return POM_ERR;
	}

	char *map = mmap(NULL, s.st_size + 1, PROT_READ, MAP_PRIVATE, fd, 0);

	if (map == MAP_FAILED) {
		close(fd);
		return POM_ERR;
	}

	size_t size = s.st_size;
	char *pos, *next_pos = map;

	unsigned int line_num = 1;

	while (next_pos) {
		pos = next_pos;

		// split the line
		char *end = memchr(pos, '\n', size);
		size_t line_size = 0;
		if (end) {
			next_pos = end + 1;
			line_size = end - pos;
		} else {
			next_pos = NULL;
			line_size = size;
		}
		size -= line_size;

		char *line = NULL;
		line = malloc(line_size + 1);

		memcpy(line, pos, line_size);
		line[line_size] = 0;
		
		// Remove comments
		char *hash = strchr(line, '#');
		if (hash)
			*hash = 0;

		int tok_num = 0;

		char *name = NULL, *ext = NULL, *type = NULL;

		int i;
		for (i = 0; i < line_size && *(line + i); i++) {
			if (!isblank(*(line + i))) {
				switch (tok_num) {
					case 0:
						name = line + i;
						tok_num++;
						while (*(line + i + 1) && !isblank(*(line + i + 1)))
							i++;
						break;
					case 1:
						ext = line + i;
						tok_num++;
						while (*(line + i + 1) && !isblank(*(line + i + 1)))
							i++;
						break;
					case 2:
						type = line + i;
						tok_num++;
						while (*(line + i + 1) && !isblank(*(line + i + 1)))
							i++;
						break;
					default:
						pom_log(POM_LOG_ERR "Error while parsing mime types database : invalid extra token %s at line %u", line + i, line_num);
						free(line);
						munmap(map, s.st_size);
						close(fd);
						target_http_mime_types_cleanup_db(priv);
						return POM_ERR;
				}

			} else {
				*(line + i) = 0;
			}

		}

		if (!name && !ext && !type) {
			free(line);
			continue;
		}

		if (!name || !ext || !type) {
			pom_log(POM_LOG_ERR "Error while parsing mime types database : line %u is incomplete", line_num);
			free(line);
			munmap(map, s.st_size);
			close(fd);
			target_http_mime_types_cleanup_db(priv);
			return POM_ERR;
		}

		priv->mime_types_size++;
		priv->mime_types = realloc(priv->mime_types, sizeof(struct http_mime_type_entry) * priv->mime_types_size);

		struct http_mime_type_entry *tmp = &priv->mime_types[priv->mime_types_size - 1];
		memset(tmp, 0, sizeof(struct http_mime_type_entry));
		tmp->name = malloc(strlen(name) + 1);
		strcpy(tmp->name, name);
		tmp->extension = malloc(strlen(ext) + 1);
		strcpy(tmp->extension, ext);

		if (!strcmp(type, "bin"))
			tmp->type = HTTP_MIME_TYPE_BIN;
		else if (!strcmp(type, "img"))
			tmp->type = HTTP_MIME_TYPE_IMG;
		else if (!strcmp(type, "vid"))
			tmp->type = HTTP_MIME_TYPE_VID;
		else if (!strcmp(type, "snd"))
			tmp->type = HTTP_MIME_TYPE_SND;
		else if (!strcmp(type, "txt"))
			tmp->type = HTTP_MIME_TYPE_TXT;
		else if (!strcmp(type, "doc"))
			tmp->type = HTTP_MIME_TYPE_DOC;
		else {
			pom_log(POM_LOG_ERR "Error while parsing mime types database : unknown type \"%s\" at line %u", type, line_num);
			free(line);
			munmap(map, s.st_size);
			close(fd);
			target_http_mime_types_cleanup_db(priv);
			return POM_ERR;
		}

		free(line);

		line_num++;
	}




	munmap(map, s.st_size);
	close(fd);

	// Allocate the hash table (4 times the size of the normal table)
	

	priv->mime_types_hash = malloc(sizeof(struct http_mime_type_hash_entry) * priv->mime_types_size * HTTP_MIME_TYPE_HASH_SIZE_RATIO);
	memset(priv->mime_types_hash, 0, sizeof(struct http_mime_type_hash_entry) * priv->mime_types_size * HTTP_MIME_TYPE_HASH_SIZE_RATIO);	

	int i;
	for (i = 0; i < priv->mime_types_size; i++) {
		uint32_t hash = jhash(priv->mime_types[i].name, strlen(priv->mime_types[i].name), HTTP_MIME_TYPE_HASH_INITVAL);
		hash %= priv->mime_types_size * HTTP_MIME_TYPE_HASH_SIZE_RATIO;
		struct http_mime_type_hash_entry *tmp = malloc(sizeof(struct http_mime_type_hash_entry));
		memset(tmp, 0, sizeof(struct http_mime_type_hash_entry));
		tmp->id = i;
		tmp->next = priv->mime_types_hash[hash];
		priv->mime_types_hash[hash] = tmp;

	}

	return POM_OK;

}


int target_http_mime_type_get_id(struct target_priv_http *priv, char *mime_type) {

	uint32_t hash = jhash(mime_type, strlen(mime_type), HTTP_MIME_TYPE_HASH_INITVAL);	
	hash %= priv->mime_types_size * HTTP_MIME_TYPE_HASH_SIZE_RATIO;

	if (priv->mime_types_hash[hash]) {
		if (priv->mime_types_hash[hash]->next) {
			struct http_mime_type_hash_entry *tmp = priv->mime_types_hash[hash];
			while (tmp) {
				if (!strcmp(priv->mime_types[tmp->id].name, mime_type))
					return tmp->id;
				tmp = tmp->next;
			}

		} else {
			return priv->mime_types_hash[hash]->id;
		}
	}

	pom_log(POM_LOG_DEBUG "Unknown mime-type %s", mime_type);
	return HTTP_MIME_TYPE_UNK;

}


int target_http_mime_types_cleanup_db(struct target_priv_http *priv) {


	if (priv->mime_types) {
		int i;
		for (i = 0; i < priv->mime_types_size; i++) {
			if (priv->mime_types[i].name)
				free(priv->mime_types[i].name);
			if (priv->mime_types[i].extension)
				free(priv->mime_types[i].extension);

		}
		free(priv->mime_types);
		priv->mime_types = NULL;
	}

	if (priv->mime_types_hash) {

		int i;
		for (i = 0; i < priv->mime_types_size * HTTP_MIME_TYPE_HASH_SIZE_RATIO; i++) {
			while (priv->mime_types_hash[i]) {
				struct http_mime_type_hash_entry *tmp = priv->mime_types_hash[i];
				priv->mime_types_hash[i] = tmp->next;
				free(tmp);
			}
		}
	
		free(priv->mime_types_hash);
		priv->mime_types_hash = NULL;
	}

	priv->mime_types_size = 0;

	return POM_OK;

}
