
#ifndef __TARGET_WAVE_H__
#define __TARGET_WAVE_H__


#include "modules_common.h"
#include "rules.h"

struct au_hdr {

	char magic[4];
	__u32 hdr_size;
	__u32 data_size;
	__u32 encoding;
	__u32 sample_rate;
	__u32 channels;


};

struct target_priv_wave {

	char prefix[NAME_MAX];

};

struct target_conntrack_priv_wave {

	int fd;
	__u16 last_seq;
	unsigned int total_size;
	unsigned int payload_type;

};

int target_register_wave();

int target_init_wave(struct target *t);
int target_process_wave(struct target *t, struct rule_node *node, void *frame, unsigned int len);
int target_close_connection_wave(void *conntrack_priv);
int target_cleanup_wave(struct target *t);

#endif
