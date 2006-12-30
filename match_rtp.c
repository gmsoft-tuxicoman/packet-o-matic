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



#include "match_rtp.h"

#define PARAMS_NUM 1

char *match_rtp_params[PARAMS_NUM][3] = {

	{ "payload", "0", "payload type to match (see RFC 1890)" },

};

int match_undefined_id;

int match_register_rtp(struct match_reg *r) {

	copy_params(r->params_name, match_rtp_params, 0, PARAMS_NUM);
	copy_params(r->params_help, match_rtp_params, 2, PARAMS_NUM);

	r->init = match_init_rtp;
	r->reconfig = match_reconfig_rtp;
	r->identify = match_identify_rtp;
	r->eval = match_eval_rtp;
	r->cleanup = match_cleanup_rtp;

	return 1;

}

int match_init_rtp(struct match *m) {

	copy_params(m->params_value, match_rtp_params, 1, PARAMS_NUM);

	match_undefined_id = (*m->match_register) ("undefined");

	return 1;

}

int match_reconfig_rtp(struct match *m) {

	if (!m->match_priv) {
		m->match_priv = malloc(sizeof(struct match_priv_rtp));
		bzero(m->match_priv, sizeof(struct match_priv_rtp));
	}

	struct match_priv_rtp *p = m->match_priv;


	return sscanf(m->params_value[0], "%hhu", &(p->payload_type));
}

int match_identify_rtp(struct layer* match, void *frame, unsigned int start, unsigned int len) {

	struct rtphdr *hdr = frame + start;

	if ((len - start) < 12) {
		ndprint("Invalid size for RTP packet\n");
		return -1;
	}

	

	int hdr_len;
	hdr_len = 12; // Len up to ssrc included
	hdr_len += hdr->csrc_count * 4;

	if (len < (hdr_len + start)) {
		ndprint("Invalid size for RTP packet\n");
		return -1;
	}

	ndprint("Processing RTP packet -> SSRC : %x | Payload type %u | SEQ : %04x", hdr->ssrc, hdr->payload_type, ntohs(hdr->seq_num));
#ifdef NDEBUG
	int i;
	for (i = 0; i < hdr->csrc_count && ((unsigned)hdr->csrc[i] + 4) < ((unsigned)frame + len); i++) {
		ndprint(" | CSRC : %x", hdr->csrc[i]);
	}
#endif
	if (hdr->extension) {
		struct rtphdrext *ext;
		ext = frame + start + hdr_len;
		hdr_len += ntohs(ext->length);
		ndprint(" | Extension header %u bytes", ntohs(ext->length));
		if (len < (hdr_len + start)) {
			ndprint(" Invalid size for RTP packet\n");
			return -1;
		}
	}
	match->payload_start = start + hdr_len;
	match->payload_size = len - match->payload_start;

	if (hdr->padding) {
		match->payload_size = *(((unsigned char*) (frame)) + len - 1);
		ndprint(" | Padding %u bytes", *(((unsigned char*) (frame)) + len - 1));
	}

	ndprint(" | SIZE %u\n", match->payload_size);

	return match_undefined_id;

}
	
int match_eval_rtp(struct match* match, void *frame, unsigned int start, unsigned int len, struct layer *l) {

	struct rtphdr *hdr = frame + start;
	struct match_priv_rtp *mp = match->match_priv;

	if (hdr->payload_type != mp->payload_type)
		return 0;
	
	return 1;


}

int match_cleanup_rtp(struct match *m) {

	clean_params(m->params_value, PARAMS_NUM);

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
