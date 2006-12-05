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

#include "target_wave.h"
#include "match_rtp.h"

#define PARAMS_NUM 1
char *target_wave_params[PARAMS_NUM][3] = {
	{ "prefix", "rtp", "prefix of wave files including directory"},
};

unsigned int match_rtp_id;

struct target_functions *tg_functions;

int target_register_wave(struct target_reg *r, struct target_functions *tg_funcs) {

	copy_params(r->params_name, target_wave_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_wave_params, 2, PARAMS_NUM);

	r->init = target_init_wave;
	r->process = target_process_wave;
	r->close_connection = target_close_connection_wave;
	r->cleanup = target_cleanup_wave;

	tg_functions = tg_funcs;

	return 1;

}

int target_cleanup_wave(struct target *t) {

	clean_params(t->params_value, PARAMS_NUM);

	return 1;
}


int target_init_wave(struct target *t) {

	copy_params(t->params_value, target_wave_params, 1, PARAMS_NUM);

	match_rtp_id = (*tg_functions->match_register) ("rtp");

	return 1;
}



int target_process_wave(struct target *t, struct rule_node *node, void *frame, unsigned int len) {

	unsigned int start = node_find_payload_start(node);
	unsigned int size = node_find_payload_size(node);

	// Do not create a file is there is nothing to save
	if (start >= len)
		return 1;

	struct conntrack_entry *ce;

	ce = (*tg_functions->conntrack_get_entry) (node, frame);

	struct target_conntrack_priv_wave *cp;

	cp = (*tg_functions->conntrack_get_priv) (t, ce);

	int rtp_start = node_find_header_start(node, match_rtp_id);
	struct rtphdr *rtphdr;
	rtphdr = frame + rtp_start;

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
				ndprint("WAVE: Payload type %u not supported\n", rtphdr->payload_type);
				free(auhdr);
				return 0;

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
		struct timeval tv;
		struct tm *tmp;
		gettimeofday(&tv, NULL);
		tmp = localtime(&tv.tv_sec);
		strftime(outstr, 20, format, tmp);

		strcpy(filename, t->params_value[0]);
		strcat(filename, outstr);
		sprintf(outstr, "%u", (unsigned int)tv.tv_usec);
		strcat(filename, outstr);
		strcat(filename, ".au");
		cp->fd = open(filename, O_RDWR | O_CREAT, 0666);

		if (cp->fd == -1) {
			free(cp);
			dprint("Unable to open file %s for writing : %s\n", filename, strerror(errno));
			return -1;
		}

		ndprint("%s opened\n", filename);

		(*tg_functions->conntrack_add_priv) (t, cp, ce);



		cp->last_seq = ntohs(rtphdr->seq_num) - 1;

		ndprint("Last seq 1 for fd %u is %u\n", cp->fd, cp->last_seq);

		write(cp->fd, auhdr, sizeof(struct au_hdr));

		free(auhdr);

	}



	__u16 cur_seq = ntohs(rtphdr->seq_num);
	
	cp->last_seq++;

	ndprint("Last seq for fd %u is %u\n", cp->fd, cp->last_seq);

	if (cp->last_seq < cur_seq) {
		char *buffer = malloc(size);
		switch (rtphdr->payload_type) {
			case 1: // G.711U
			case 8: // G.711A
				memset(buffer, 0x55, size);
				break;
			default: 
				memset(buffer, 0x0, size);
		}

		while (cp->last_seq != cur_seq) { // Fill with 0
			ndprint("RTP Packet missed, last seq %u, cur seq %u\n", cp->last_seq, cur_seq);
			write(cp->fd, buffer, size);
			cp->last_seq++;
		}

		free(buffer);
	}

	cp->total_size += size;

	write(cp->fd, frame + start, size);

	return 1;
};

int target_close_connection_wave(void *conntrack_priv) {

	ndprint("Closing connection 0x%x\n", (unsigned) conntrack_priv);

	struct target_conntrack_priv_wave *cp;
	cp = conntrack_priv;

	lseek(cp->fd, 8, SEEK_SET);
	__u32 size = htonl(cp->total_size);
	write(cp->fd, &size , 4);


	close(cp->fd);

	free(cp);
	
	return 1;

}



