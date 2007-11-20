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

#include "target_wave.h"
#include "match_rtp.h"

#include "ptype_string.h"

unsigned int match_rtp_id;

struct target_functions *tf;
struct target_mode *mode_default;

int target_register_wave(struct target_reg *r, struct target_functions *tg_funcs) {

	r->init = target_init_wave;
	r->process = target_process_wave;
	r->close = target_close_wave;
	r->cleanup = target_cleanup_wave;

	tf = tg_funcs;

	match_rtp_id = (*tf->match_register) ("rtp");

	mode_default = (*tg_funcs->register_mode) (r->type, "default", "Dump each RTP stream into separate files");

	if (!mode_default)
		return POM_ERR;

	(*tg_funcs->register_param) (mode_default, "prefix", "dump", "Prefix of dumped filenames including path");

	return POM_OK;

}

int target_init_wave(struct target *t) {

	struct target_priv_wave *priv = malloc(sizeof(struct target_priv_wave));
	bzero(priv, sizeof(struct target_priv_wave));

	t->target_priv = priv;

	priv->prefix = (*tf->ptype_alloc) ("string", NULL);
	if (!priv->prefix) {
		target_cleanup_wave(t);
		return POM_ERR;
	}

	(*tf->register_param_value) (t, mode_default, "prefix", priv->prefix);


	return POM_OK;
}


int target_close_wave(struct target *t) {

	struct target_priv_wave *priv = t->target_priv;

	while (priv->ct_privs) {
		(*tf->conntrack_remove_priv) (priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_wave(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

int target_cleanup_wave(struct target *t) {

	struct target_priv_wave *priv = t->target_priv;

	if (priv) {

		(*tf->ptype_cleanup) (priv->prefix);
		free(priv);
	}

	return POM_OK;
}




int target_process_wave(struct target *t, struct frame *f) {

	struct target_priv_wave *priv = t->target_priv;

	struct layer *rtpl = f->l;
	while (rtpl) {
		if (rtpl->type == match_rtp_id)
			break;
		rtpl = rtpl->next;
	}

	if (!rtpl) {
		(*tf->pom_log) (POM_LOG_INFO "No RTP header found in this packet\r\n");
		return POM_OK;
	}

	// Do not create a file is there is nothing to save
	if (rtpl->payload_size == 0)
		return POM_OK;
	
	if (!f->ce)
		(*tf->conntrack_create_entry) (f);

	struct target_conntrack_priv_wave *cp;

	cp = (*tf->conntrack_get_priv) (t, f->ce);

	int rtp_start = rtpl->prev->payload_start;
	struct rtphdr *rtphdr;
	rtphdr = f->buff + rtp_start;

	if (!cp) {


		// Allocate the audio header
		struct au_hdr *auhdr;
		auhdr = malloc(sizeof(struct au_hdr));
		bzero(auhdr, sizeof(struct au_hdr));
		memcpy(auhdr->magic, ".snd", 4);
		auhdr->hdr_size = htonl(24);
		auhdr->data_size = 0;
		switch (rtphdr->payload_type) {
			case 0: // G.711U
				auhdr->encoding = htonl(1);
				break;
			case 8: // G.711A
				auhdr->encoding = htonl(27);
				break;
			case 9: // G.722
				auhdr->encoding = htonl(24);
				break;
			default:
				(*tf->pom_log) (POM_LOG_DEBUG "WAVE: Payload type %u not supported\r\n", rtphdr->payload_type);
				free(auhdr);
				return POM_OK;

		}
		auhdr->sample_rate = htonl(8000);
		auhdr->channels = htonl(1);

		// New connection
		cp = malloc(sizeof(struct target_conntrack_priv_wave));
		bzero(cp, sizeof(struct target_conntrack_priv_wave));

		char filename[NAME_MAX];

		char outstr[20];
		bzero(outstr, 20);
		// YYYYMMDD-HHMMSS-UUUUUU
		char *format = "-%Y%m%d-%H%M%S-";
		struct tm *tmp;
	        tmp = localtime((time_t*)&f->tv.tv_sec);

		strftime(outstr, 20, format, tmp);

		strcpy(filename, PTYPE_STRING_GETVAL(priv->prefix));
		strcat(filename, outstr);
		sprintf(outstr, "%u", (unsigned int)f->tv.tv_usec);
		strcat(filename, outstr);
		strcat(filename, ".au");
		cp->fd = (*tf->file_open) (f->l, filename, O_RDWR | O_CREAT, 0666);

		if (cp->fd == -1) {
			free(cp);
			char errbuff[256];
			strerror_r(errno, errbuff, 256);
			(*tf->pom_log) (POM_LOG_ERR "Unable to open file %s for writing : %s\r\n", filename, errbuff);
			return POM_ERR;
		}

		(*tf->pom_log) (POM_LOG_TSHOOT "%s opened\r\n", filename);

		(*tf->conntrack_add_priv) (cp, t, f->ce, target_close_connection_wave);
		
		cp->ce = f->ce;
		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;


		cp->last_seq = ntohs(rtphdr->seq_num) - 1;

		write(cp->fd, auhdr, sizeof(struct au_hdr));

		free(auhdr);

	}



	uint16_t cur_seq = ntohs(rtphdr->seq_num);
	
	cp->last_seq++;

	if (cp->last_seq < cur_seq) {
		char *buffer = malloc(rtpl->payload_size);
		switch (rtphdr->payload_type) {
			case 1: // G.711U
			case 8: // G.711A
				memset(buffer, 0x55, rtpl->payload_size);
				break;
			default: 
				memset(buffer, 0x0, rtpl->payload_size);
		}

		while (cp->last_seq != cur_seq) { // Fill with 0
			write(cp->fd, buffer, rtpl->payload_size);
			cp->last_seq++;
		}

		free(buffer);
	}

	cp->total_size += rtpl->payload_size;

	write(cp->fd, f->buff + rtpl->payload_start, rtpl->payload_size);

	return POM_OK;
};

int target_close_connection_wave(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	(*tf->pom_log) (POM_LOG_TSHOOT "Closing connection 0x%lx\r\n", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_wave *cp;
	cp = conntrack_priv;

	lseek(cp->fd, 8, SEEK_SET);
	uint32_t size = htonl(cp->total_size);
	write(cp->fd, &size , 4);

	close(cp->fd);

	struct target_priv_wave *priv = t->target_priv;

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;


	free(cp);
	
	return POM_OK;

}



