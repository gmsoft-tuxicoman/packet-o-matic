
#include "input_pcap.h"


int input_register_pcap(struct input_reg *r) {

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

	return 1;

}

int input_cleanup_pcap(struct input *i) {

	if (i->input_priv)
		free(i->input_priv);

	return 1;

};

int input_open_pcap(struct input *i, void *params) {


	struct input_open_pcap_params *op = params;
	struct input_priv_pcap *p = i->input_priv;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = 0;
	
	if (op->filename) {
		dprint("Error opening file %s for reading\n", op->filename);
		p->p = pcap_open_offline(op->filename, errbuf);
	} else {
		if (!op->interface)
			op->interface = "any";
		if (op->snaplen < 64)
			op->snaplen = 64;
		dprint("Opening interface %s with a snaplen of %u\n", op->interface, op->snaplen);
		p->p = pcap_open_live(op->interface, op->snaplen, op->promisc, 0, errbuf);
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
