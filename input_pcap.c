
#include "input_pcap.h"

#define PARAMS_NUM 4

char *input_pcap_params[PARAMS_NUM][3] = {
	{ "filename", "", "Filename to read packets from. reads from an interface if empty" },
	{ "interface", "eth0", "Interface to read from" },
	{ "snaplen", "1500", "Snaplen if reading from an iface" },
	{ "promisc", "0", "Set the interface in promisc mode if != 0" },
};


int input_register_pcap(struct input_reg *r) {

	copy_params(r->params_name, input_pcap_params, 0, PARAMS_NUM);
	copy_params(r->params_help, input_pcap_params, 2, PARAMS_NUM);


	r->init = input_init_pcap;
	r->open = input_open_pcap;
	r->read = input_read_pcap;
	r->close = input_close_pcap;
	r->cleanup = input_cleanup_pcap;

	return 1;
}


int input_init_pcap(struct input *i) {

	i->input_priv = malloc(sizeof(struct input_priv_pcap));
	bzero(i->input_priv, sizeof(struct input_priv_pcap));

	copy_params(i->params_value, input_pcap_params, 1, PARAMS_NUM);

	return 1;

}

int input_cleanup_pcap(struct input *i) {

	clean_params(i->params_value, PARAMS_NUM);

	if (i->input_priv)
		free(i->input_priv);

	return 1;

};

int input_open_pcap(struct input *i) {


	struct input_priv_pcap *p = i->input_priv;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = 0;

	char filename[256];
	bzero(filename, 256);
	sscanf(i->params_value[0], "%255s", filename);
	
	if (strlen(filename) > 0) {
		dprint("Error opening file %s for reading\n", filename);
		p->p = pcap_open_offline(filename, errbuf);
	} else {
		char interface[256];
		bzero(interface, 256);
		sscanf(i->params_value[1], "%255s", interface);

		int snaplen;
		sscanf(i->params_value[2], "%u", &snaplen);

		int promisc;
		sscanf(i->params_value[3], "%u", &promisc);
		if (snaplen < 64)
			snaplen = 64;
		dprint("Opening interface %s with a snaplen of %u\n", interface, snaplen);
		p->p = pcap_open_live(interface, snaplen, promisc, 0, errbuf);
	}

	if (strlen(errbuf) > 0)
		dprint("PCAP warning : %s\n", errbuf);
	

	if (p->p)	
		dprint("Pcap opened successfullly\n");
	else {
		dprint("Error while opening pcap input\n");
		return 0;
	}
	
	return 1;
}



int input_read_pcap(struct input *i, unsigned char *buffer, unsigned int bufflen) {

	struct input_priv_pcap *p = i->input_priv;
	const u_char *next_pkt;

	struct pcap_pkthdr *phdr;

	int result;
	result = pcap_next_ex(p->p, &phdr, &next_pkt);

	if (result < 0) {
		dprint("Error while reading packet.\n");
		return -1;
	}

	if (bufflen < phdr->caplen) {
		dprint("Please increase your read buffer. Provided %u, needed %u\n", bufflen, phdr->caplen);
		phdr->caplen = bufflen;
		
	}
	memcpy(buffer, next_pkt, phdr->caplen);


	return phdr->caplen;
}

int input_close_pcap(struct input *i) {

	struct input_priv_pcap *p = i->input_priv;
	if (!p)
		return 0;
	

	pcap_close(p->p);

	return 1;

}
