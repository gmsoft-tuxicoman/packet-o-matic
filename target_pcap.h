
#ifndef __TARGET_PCAP_H__
#define __TARGET_PCAP_H__

#include <pcap.h>
#include <sys/time.h>

#include "modules_common.h"
#include "rules.h"

#define SNAPLEN 2000

struct target_priv_pcap {

	pcap_dumper_t *pdump;
	pcap_t *p;
	unsigned int size;

};

int target_init_pcap(struct target *t);
int target_open_pcap(struct target *t);
int target_process_pcap(struct target *t, struct rule_node *node, void *frame, unsigned int len);
int target_close_pcap(struct target *t);
int target_cleanup_pcap(struct target *t);



#endif
