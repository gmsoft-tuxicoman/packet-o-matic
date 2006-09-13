

#ifndef __INPUT_PCAP_H__
#define __INPUT_PCAP_H__


#include <pcap.h>

#include "common.h"

#include "input.h"



struct input_open_pcap_params {

	char *filename; // Filename or NULL to open an interface
	char *interface; // Interface name to open or "any"
	int snaplen; // Snaplen if reading from an iface
	int promisc; // Switch the specified interface into promisc mode ?
	

};

struct input_priv_pcap {

	pcap_t *p;

};


int input_init_pcap(struct input *i);
int input_open_pcap(struct input *i, void *params);
int input_read_pcap(struct input *i, unsigned char *buffer, unsigned int bufflen);
int input_close_pcap(struct input *i);
int input_cleanup_pcap(struct input *i);


#endif

