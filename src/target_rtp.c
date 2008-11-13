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

#include "target_rtp.h"

#include "ptype_string.h"
#include "ptype_uint16.h"

#include <rtp.h>

static unsigned int match_rtp_id;

static struct target_mode *mode_default;

int target_register_rtp(struct target_reg *r) {

	r->init = target_init_rtp;
	r->process = target_process_rtp;
	r->close = target_close_rtp;
	r->cleanup = target_cleanup_rtp;

	match_rtp_id = match_register("rtp");

	mode_default = target_register_mode(r->type, "default", "Dump each RTP stream into separate files");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "prefix", "dump", "Prefix of dumped filenames including path");
	target_register_param(mode_default, "jitter_buffer", "4000", "Data to buffer while waiting for reverse direction channels");

	return POM_OK;

}

static int target_init_rtp(struct target *t) {

	struct target_priv_rtp *priv = malloc(sizeof(struct target_priv_rtp));
	memset(priv, 0, sizeof(struct target_priv_rtp));

	t->target_priv = priv;

	priv->prefix = ptype_alloc("string", NULL);
	priv->jitter_buffer = ptype_alloc("uint16", "bytes");
	if (!priv->prefix || !priv->jitter_buffer) {
		target_cleanup_rtp(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "prefix", priv->prefix);
	target_register_param_value(t, mode_default, "jitter_buffer", priv->jitter_buffer);


	return POM_OK;
}


static int target_close_rtp(struct target *t) {

	struct target_priv_rtp *priv = t->target_priv;

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_rtp(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

static int target_cleanup_rtp(struct target *t) {

	struct target_priv_rtp *priv = t->target_priv;

	if (priv) {

		ptype_cleanup(priv->prefix);
		ptype_cleanup(priv->jitter_buffer);
		free(priv);
	}

	return POM_OK;
}

static int target_process_rtp(struct target *t, struct frame *f) {

	struct target_priv_rtp *priv = t->target_priv;

	struct layer *rtpl = f->l;
	while (rtpl) {
		if (rtpl->type == match_rtp_id)
			break;
		rtpl = rtpl->next;
	}

	if (!rtpl) {
		pom_log(POM_LOG_INFO "No RTP header found in this packet");
		return POM_OK;
	}

	// Skip if there is no payload
	if (rtpl->payload_size <= 0)
		return POM_OK;

	int rtp_start = rtpl->prev->payload_start;
	struct rtphdr *rtphdr;
	rtphdr = f->buff + rtp_start;

	// Make sure we support this payload type
	switch (rtphdr->payload_type) {
		case RTP_CODEC_G711U:
		case RTP_CODEC_G721:
		case RTP_CODEC_G711A:
		case RTP_CODEC_G722:
			break;
		default:
			pom_log(POM_LOG_DEBUG "RTP: Payload type %u not supported", rtphdr->payload_type);
			return POM_OK;

	}


	if (!f->ce)
		if (conntrack_create_entry(f) == POM_ERR)
			return POM_OK;

	struct target_conntrack_priv_rtp *cp;

	cp = conntrack_get_target_priv(t, f->ce);

	if (!cp) {

		// New connection
		cp = malloc(sizeof(struct target_conntrack_priv_rtp));
		memset(cp, 0, sizeof(struct target_conntrack_priv_rtp));
		
		conntrack_add_target_priv(cp, t, f->ce, target_close_connection_rtp);
		
		cp->ce = f->ce;
		cp->payload_type = rtphdr->payload_type;

		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;

		// Compute filename right away
		char filename[NAME_MAX + 1];
		char outstr[20];
		memset(outstr, 0, 20);
		// YYYYMMDD-HHMMSS-UUUUUU
		char *format = "-%Y%m%d-%H%M%S-";
		struct tm tmp;
		localtime_r((time_t*)&f->tv.tv_sec, &tmp);

		strftime(outstr, 20, format, &tmp);

		strcpy(filename, PTYPE_STRING_GETVAL(priv->prefix));
		strcat(filename, outstr);
		sprintf(outstr, "%u", (unsigned int)f->tv.tv_usec);
		strcat(filename, outstr);
		strcat(filename, ".au");
		if (layer_field_parse(f->l, filename, cp->filename, NAME_MAX) == POM_ERR)
			return POM_ERR;


		cp->fd = -1;


	}

	if (rtphdr->payload_type != cp->payload_type) {
		// payload type different for each direction is not supported
		pom_log(POM_LOG_DEBUG "RTP: Payload type %u does not mach initial payload type : %u", rtphdr->payload_type, cp->payload_type);
		return POM_OK;
	}

	int dir = cp->ce->direction;


	if (!cp->buffer[dir].buff) {
		if (cp->channels != 0) {
			// since channels > 0, something was written to the file and we have to ignore this direction
			return POM_OK;
		}
		cp->buffer[dir].buff = malloc(PTYPE_UINT16_GETVAL(priv->jitter_buffer));
		memset(cp->buffer[dir].buff, 0, PTYPE_UINT16_GETVAL(priv->jitter_buffer));
		cp->buffer[dir].buff_size = PTYPE_UINT16_GETVAL(priv->jitter_buffer);
		cp->last_seq[dir] = ntohs(rtphdr->seq_num) - 1;

	}





	uint16_t cur_seq = ntohs(rtphdr->seq_num);
	
	cp->last_seq[dir]++;

	if (cp->last_seq[dir] < cur_seq) {
		char *buffer = malloc(rtpl->payload_size);
		switch (rtphdr->payload_type) {
			case RTP_CODEC_G711U: // G.711U
			case RTP_CODEC_G711A: // G.711A
				memset(buffer, 0x55, rtpl->payload_size);
				break;
			default: 
				memset(buffer, 0x0, rtpl->payload_size);
		}

		while (cp->last_seq[dir] != cur_seq) { // Fill with silence
			if (write_packet(cp, priv, dir, buffer, rtpl->payload_size) == POM_ERR) {
				free(buffer);
				return POM_ERR;
			}
			cp->last_seq[dir]++;
		}

		free(buffer);
	}

	return write_packet(cp, priv, dir, f->buff + rtpl->payload_start, rtpl->payload_size);
}

static int write_packet(struct target_conntrack_priv_rtp *cp, struct target_priv_rtp *priv, int dir, void *data, int len) {


	struct rtp_buffer* buff = &cp->buffer[dir];
	if (len + buff->buff_pos > buff->buff_size) {
		// buffer overflow, write stuff out to disk
		if (cp->fd == -1) {
			if (open_file(priv, cp) == POM_ERR)
				return POM_ERR;
		}

		int rev_dir;
		if (dir == CE_DIR_FWD)
			rev_dir = CE_DIR_REV;
		else
			rev_dir = CE_DIR_FWD;
		
		// check if flush_buffers will have any effect
		if (cp->channels == 2) {
			char silence;
			switch (cp->payload_type) {
				case RTP_CODEC_G711U:
				case RTP_CODEC_G711A:
					silence = 0x55;
					break;
				default:
					silence = 0;
			}
			
			if (cp->buffer[dir].buff_pos == 0) {
				cp->buffer[dir].buff_pos = cp->buffer[dir].buff_size / 2;
				memset(cp->buffer[dir].buff, silence, cp->buffer[dir].buff_pos);
			} else if (cp->buffer[rev_dir].buff_pos == 0) {
				cp->buffer[rev_dir].buff_pos = cp->buffer[rev_dir].buff_size / 2;
				memset(cp->buffer[rev_dir].buff, silence, cp->buffer[rev_dir].buff_pos);
			}

		}

		flush_buffers(cp, dir);	

	}


	// buffer should have enough space now

	memcpy(buff->buff + buff->buff_pos, data, len);
	buff->buff_pos += len;

	return POM_OK;

}

static int open_file(struct target_priv_rtp *priv, struct target_conntrack_priv_rtp *cp) {


	cp->fd = target_file_open(NULL, cp->filename, O_RDWR | O_CREAT, 0666);

	if (cp->fd == -1) {
		char errbuff[256];
		strerror_r(errno, errbuff, 256);
		pom_log(POM_LOG_ERR "Unable to open file %s for writing : %s", cp->filename, errbuff);
	} else
		pom_log(POM_LOG_TSHOOT "%s opened", cp->filename);
	
	struct au_hdr auhdr;
	memset(&auhdr, 0, sizeof(struct au_hdr));
	memcpy(auhdr.magic, AU_MAGIC, sizeof(auhdr.magic));
	auhdr.hdr_size = htonl(sizeof(struct au_hdr));
	auhdr.data_size = 0;
	switch (cp->payload_type) {
		case RTP_CODEC_G711U:
			auhdr.encoding = htonl(AU_CODEC_MULAW);
			break;
		case RTP_CODEC_G721:
			auhdr.encoding = htonl(AU_CODEC_ADPCM_G721);
			break;
		case RTP_CODEC_G711A:
			auhdr.encoding = htonl(AU_CODEC_ALAW);
			break;
		case RTP_CODEC_G722:
			auhdr.encoding = htonl(AU_CODEC_ADPCM_G722);
			break;
		default:
			pom_log(POM_LOG_DEBUG "RTP: Payload type %u not supported", cp->payload_type);
			return POM_OK;

	}
	auhdr.sample_rate = htonl(8000);

	cp->channels = 0;
	if (cp->buffer[CE_DIR_FWD].buff)
		cp->channels++;
	if (cp->buffer[CE_DIR_REV].buff)
		cp->channels++;

	if (cp->channels == 0) {
		pom_log(POM_LOG_ERR "Internal error in target_rtp. No channel found when writing file");
		return POM_ERR;
	}

	auhdr.data_size = AU_UNKNOWN_SIZE;
	auhdr.channels = htonl(cp->channels);

	if (write(cp->fd, &auhdr, sizeof(struct au_hdr)) < sizeof(struct au_hdr))
		return POM_ERR;

	return POM_OK;
}


static int target_close_connection_rtp(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_rtp *cp;
	cp = conntrack_priv;

	if (cp->channels == 2) {
		char silence;
		switch (cp->payload_type) {
			case RTP_CODEC_G711U:
			case RTP_CODEC_G711A:
				silence = 0x55;
				break;
			default:
				silence = 0;
		}
		int pad = 0;
		// make sure we have the same amount of bytes in both buffers
		if (cp->buffer[CE_DIR_FWD].buff_pos > cp->buffer[CE_DIR_REV].buff_pos) {
			pad = cp->buffer[CE_DIR_FWD].buff_pos - cp->buffer[CE_DIR_REV].buff_pos;
			memset(cp->buffer[CE_DIR_REV].buff + cp->buffer[CE_DIR_REV].buff_pos, silence, pad);
			cp->buffer[CE_DIR_REV].buff_pos = cp->buffer[CE_DIR_FWD].buff_pos;

		} else if (cp->buffer[CE_DIR_REV].buff_pos > cp->buffer[CE_DIR_FWD].buff_pos) {
			pad = cp->buffer[CE_DIR_REV].buff_pos - cp->buffer[CE_DIR_FWD].buff_pos;
			memset(cp->buffer[CE_DIR_FWD].buff + cp->buffer[CE_DIR_FWD].buff_pos, silence, pad);
			cp->buffer[CE_DIR_FWD].buff_pos = cp->buffer[CE_DIR_REV].buff_pos;

		}
	}

	struct target_priv_rtp *priv = t->target_priv;


	if (cp->fd == -1) {
		if (open_file(priv, cp) == POM_ERR)
			return POM_ERR;
	}


	flush_buffers(cp, CE_DIR_FWD);

	lseek(cp->fd, 8, SEEK_SET);
	uint32_t size = htonl(cp->total_size);
	write(cp->fd, &size , 4);

	close(cp->fd);

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;

	int i;
	for (i = 0; i < 2; i++) {
		if (cp->buffer[i].buff)
			free(cp->buffer[i].buff);
	}

	free(cp);
	
	return POM_OK;

}

static int flush_buffers(struct target_conntrack_priv_rtp *cp, int dir) {

	struct rtp_buffer* buff = &cp->buffer[dir];
	if (cp->channels == 1) {
		write(cp->fd, buff->buff, buff->buff_pos);
		cp->total_size += buff->buff_pos;
		buff->buff_pos = 0;
	} else { // channels = 2
		int read_pos = 0;
		switch (cp->payload_type) {
			case RTP_CODEC_G711U: // 8 bit interleaving
			case RTP_CODEC_G711A:

				while (read_pos < cp->buffer[CE_DIR_FWD].buff_pos && read_pos < cp->buffer[CE_DIR_REV].buff_pos) {
					write(cp->fd, cp->buffer[CE_DIR_FWD].buff + read_pos, 1);
					write(cp->fd, cp->buffer[CE_DIR_REV].buff + read_pos, 1);
					read_pos++;
					cp->total_size += 2;
				}

				break;

			case RTP_CODEC_G722: // 16 bit interleaving. XXX : Most likely broken for G.722, need to check
				while (read_pos < cp->buffer[CE_DIR_FWD].buff_pos && read_pos < cp->buffer[CE_DIR_REV].buff_pos) {
					write(cp->fd, cp->buffer[CE_DIR_FWD].buff + read_pos, 2);
					write(cp->fd, cp->buffer[CE_DIR_REV].buff + read_pos, 2);
					read_pos += 2;
					cp->total_size += 4;
				}

				break;

			case RTP_CODEC_G721: // 4 bit interleaving
				while (read_pos < cp->buffer[CE_DIR_FWD].buff_pos && read_pos < cp->buffer[CE_DIR_REV].buff_pos) {
					char buff, fwd, rev;
					fwd = *(cp->buffer[CE_DIR_FWD].buff + read_pos);
					rev = *(cp->buffer[CE_DIR_REV].buff + read_pos);

					buff = (fwd & 0xf0) | ((rev & 0xf0) >> 4);
					write(cp->fd, &buff, 1);
					buff = ((fwd & 0xf) << 4) | (rev & 0xf);
					write(cp->fd, &buff, 1);
					read_pos++;
					cp->total_size += 2;
				}
				break;	

			default:
				return POM_ERR;

		}
		if (cp->buffer[CE_DIR_FWD].buff_pos - read_pos > 0) {
			memmove(cp->buffer[CE_DIR_FWD].buff, cp->buffer[CE_DIR_FWD].buff + read_pos, cp->buffer[CE_DIR_FWD].buff_pos - read_pos);
			cp->buffer[CE_DIR_FWD].buff_pos = cp->buffer[CE_DIR_FWD].buff_pos - read_pos;
		} else
			cp->buffer[CE_DIR_FWD].buff_pos = 0;

		if (cp->buffer[CE_DIR_REV].buff_pos - read_pos > 0) {
			memmove(cp->buffer[CE_DIR_REV].buff, cp->buffer[CE_DIR_REV].buff + read_pos, cp->buffer[CE_DIR_REV].buff_pos - read_pos);
			cp->buffer[CE_DIR_REV].buff_pos = cp->buffer[CE_DIR_REV].buff_pos - read_pos;
		} else
			cp->buffer[CE_DIR_REV].buff_pos = 0;

	}

	return POM_OK;
}

