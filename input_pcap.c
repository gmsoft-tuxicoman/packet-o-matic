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


#include "input_pcap.h"

#define PARAMS_NUM 4

char *input_pcap_params[PARAMS_NUM][3] = {
	{ "filename", "", "filename to read packets from. reads from an interface if empty" },
	{ "interface", "eth0", "interface to read from" },
	{ "snaplen", "1522", "snaplen if reading from an iface" },
	{ "promisc", "0", "set the interface in promisc mode if != 0" },
};


int input_register_pcap(struct input_reg *r) {

	copy_params(r->params_name, input_pcap_params, 0, PARAMS_NUM);
	copy_params(r->params_help, input_pcap_params, 2, PARAMS_NUM);


	r->init = input_init_pcap;
	r->open = input_open_pcap;
	r->get_first_layer = input_get_first_layer_pcap;
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
		p->p = pcap_open_offline(filename, errbuf);
		if (!p->p) {
			dprint("Error opening file %s for reading\n", filename);
			return 0;
		}
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
		if (!p->p) {
			dprint("Error when opening interface %s : %s\n", filename, errbuf);
			return 0;
		}
	}

	switch (pcap_datalink(p->p)) {
		case DLT_EN10MB:
			dprint("PCAP output type is ethernet\n");
			p->output_layer = (*i->match_register) ("ethernet");
			break;
		case DLT_DOCSIS:
			dprint("PCAP output type is docsis\n");
			p->output_layer = (*i->match_register) ("docsis");
			break;

		default:
			dprint("PCAP output type is undefined\n");
			p->output_layer = (*i->match_register) ("undefined");

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

int input_get_first_layer_pcap(struct input *i) {
	struct input_priv_pcap *p = i->input_priv;
	return p->output_layer;
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
