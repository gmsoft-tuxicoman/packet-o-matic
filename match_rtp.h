
#ifndef __MATCH_UDP_H__
#define __MATCH_UDP_H__

#include <endian.h>

#include "modules_common.h"
#include "match.h"

struct rtphdr {
	
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int csrc_count:4;
	unsigned int extension:1;
	unsigned int padding:1;
	unsigned int version:2;

	unsigned int payload_type:7;
	unsigned int marker:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:2;
	unsigned int padding:1;
	unsigned int extension:1;
	unsigned int csrc_count:4;

	unsigned int marker:1;
	unsigned int payload_type:7;
#else
# error "Please fix <endian.h>"
#endif
	__u16 seq_num;
	__u32 timestamp;
	__u32 ssrc;
	__u32 csrc[16];

};

struct rtphdrext {
	__u16 profile_defined;
	__u16 length;
	char *header_extension;
};



struct match_priv_rtp {

	unsigned char payload_type;

};


int match_register_rtp();

int match_register_rtp();
int match_init_rtp(struct match *m);
int match_config_rtp(struct match *m, void *params);
int match_eval_rtp(struct match* match, void* frame, unsigned int start, unsigned int len);
int match_cleanup_rtp(struct match *m);


#endif
