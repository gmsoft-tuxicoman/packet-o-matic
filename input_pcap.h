

#ifndef __INPUT_PCAP_H__
#define __INPUT_PCAP_H__


#include <pcap.h>

#include "modules_common.h"

#include "input.h"



struct input_priv_pcap {

	pcap_t *p;
	int output_layer;

};


int input_init_pcap(struct input *i);
int input_open_pcap(struct input *i);
int input_get_first_layer_pcap(struct input *i);
int input_read_pcap(struct input *i, unsigned char *buffer, unsigned int bufflen);
int input_close_pcap(struct input *i);
int input_cleanup_pcap(struct input *i);


#endif

