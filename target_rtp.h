
#ifndef __TARGET_RTP_H__
#define __TARGET_RTP_H__

#include "common.h"
#include "rules.h"

struct target_priv_rtp_wave_hdr {

	char chunk_id[4];
	__u16 chunk_size;
	char chunk_format[4];
	
	char subchunk1_id[4];
	__u16 subchunk1_size;
	__u8 audio_format;
	__u8 channels;
	__u16 sample_rate;
	__u16 byte_rate;
	__u8 block_align;
	__u16 bits_per_sample;
	char subchunk2_id[4];
	__u16 subchunk2_size;

};

struct target_priv_rtp {


	int fd;
	struct target_priv_rtp_wave_hdr wavehdr;
	__u16 last_seq;
	size_t payload_size;
	

};

int target_register_rtp();

int target_init_rtp(struct rule_target *t);
int target_open_rtp(struct rule_target *t, char *filename);
int target_process_rtp(struct rule_target *t, struct rule_node *node, void *frame, unsigned int len);
int target_close_rtp(struct rule_target *t);

#endif
