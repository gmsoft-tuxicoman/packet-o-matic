

#include "match_rtp.h"



int match_register_rtp(struct match_reg *r) {

	r->init = match_init_rtp;
	r->config = match_config_rtp;
	r->eval = match_eval_rtp;
	r->cleanup = match_cleanup_rtp;

	return 1;

}

int match_init_rtp(struct match *m) {

	return 1;

}

int match_config_rtp(struct match *m, void *params) {

	m->match_priv = params;
	return 1;
}

int match_eval_rtp(struct match* match, void *frame, unsigned int start, unsigned int len) {
	struct rtphdr *hdr = frame + start;

	if (len < 12) {
		ndprint("Invalid size for RTP packet\n");
		return 0;
	}

	

	match->next_layer = -1; // Nothing else besides payload in RTP
	int hdr_len;
	hdr_len = 12; // Len up to ssrc included
	hdr_len += hdr->csrc_count * 4;

	if (len < hdr_len) {
		ndprint("Invalid size for RTP packet\n");
		return 0;
	}

	ndprint("Processing RTP packet -> SSRC : %x | Payload type %u | SEQ : %04x", hdr->ssrc, hdr->payload_type, ntohs(hdr->seq_num));
#ifdef NDEBUG
	int i;
	for (i = 0; i < hdr->csrc_count && (hdr->csrc[i] + 4) < (frame + len); i++) {
		ndprint(" | CSRC : %x", hdr->csrc[i]);
	}
#endif
	if (hdr->extension) {
		struct rtphdrext *ext;
		ext = frame + start + hdr_len;
		hdr_len += ntohs(ext->length);
		ndprint(" | Extension header %u bytes", ntohs(ext->length));
		if (len < hdr_len) {
			ndprint(" Invalid size for RTP packet\n");
			return 0;
		}
	}
	match->next_start = start + hdr_len;
	match->next_size = len - (match->next_start);

	if (hdr->padding) {
		match->next_size = *(((unsigned char*) (frame)) + len - 1);
		ndprint(" | Padding %u bytes", *(((unsigned char*) (frame)) + len - 1));
	}

	ndprint(" | SIZE %u\n", match->next_size);

	if (!match->match_priv)
		return 1;
	
	struct match_priv_rtp *mp = match->match_priv;

	if (hdr->payload_type != mp->payload_type)
		return 0;
	
	return 1;


}

int match_cleanup_rtp(struct match *m) {

	if (m->match_priv)
		free(m->match_priv);

	return 1;

}
