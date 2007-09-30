/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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
#include "ptype_string.h"
#include "ptype_bool.h"
#include "ptype_uint16.h"

struct input_functions *i_functions;

struct input_mode *mode_interface, *mode_file;
struct ptype *p_filename, *p_interface, *p_snaplen, *p_promisc;

int input_register_pcap(struct input_reg *r, struct input_functions *i_funcs) {

	i_functions = i_funcs;

	r->init = input_init_pcap;
	r->open = input_open_pcap;
	r->read = input_read_pcap;
	r->close = input_close_pcap;
	r->cleanup = input_cleanup_pcap;
	r->getcaps = input_getcaps_pcap;
	r->unregister = input_unregister_pcap;

	mode_interface = (*i_funcs->register_mode) (r->type, "interface", "Read packets from an interface");
	mode_file = (*i_funcs->register_mode) (r->type, "file", "Read packets from a pcap file");

	if (!mode_interface || !mode_file)
		return POM_ERR;
	
	p_filename = (*i_funcs->ptype_alloc) ("string", NULL);
	p_interface = (*i_funcs->ptype_alloc) ("string", NULL);
	p_snaplen = (*i_funcs->ptype_alloc) ("uint16", "bytes");
	p_promisc = (*i_funcs->ptype_alloc) ("bool", NULL);

	if (!p_filename || !p_interface || !p_snaplen || !p_promisc) {
		input_unregister_pcap(r);
		return POM_ERR;
	}

	(*i_funcs->register_param) (mode_interface, "interface", "eth0", p_interface, "Interface to listen from");
	(*i_funcs->register_param) (mode_interface, "snaplen", "1522", p_snaplen, "Snaplen");
	(*i_funcs->register_param) (mode_interface, "promisc", "0", p_promisc, "Promiscuous");

	(*i_funcs->register_param) (mode_file, "file", "", p_filename, "PCAP file");

	return POM_OK;
}


int input_init_pcap(struct input *i) {

	i->input_priv = malloc(sizeof(struct input_priv_pcap));
	bzero(i->input_priv, sizeof(struct input_priv_pcap));

	return POM_OK;

}

int input_cleanup_pcap(struct input *i) {

	if (i->input_priv)
		free(i->input_priv);

	return POM_OK;

}

int input_unregister_pcap(struct input_reg *r) {

	(*i_functions->ptype_cleanup) (p_interface);
	(*i_functions->ptype_cleanup) (p_snaplen);
	(*i_functions->ptype_cleanup) (p_promisc);
	(*i_functions->ptype_cleanup) (p_filename);
	return POM_OK;
}

int input_open_pcap(struct input *i) {


	struct input_priv_pcap *p = i->input_priv;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = 0;

	if (i->mode == mode_file) {
		char *filename = PTYPE_STRING_GETVAL(p_filename);
		p->p = pcap_open_offline(filename, errbuf);
		if (!p->p) {
			dprint("Error opening file %s for reading\n", filename);
			return POM_ERR;
		}
	} else if (i->mode == mode_interface) {
		char *interface = PTYPE_STRING_GETVAL(p_interface);
		int snaplen = PTYPE_UINT16_GETVAL(p_snaplen);
		int promisc = PTYPE_BOOL_GETVAL(p_promisc);
		if (snaplen < 64)
			snaplen = 64;
		dprint("Opening interface %s with a snaplen of %u\n", interface, snaplen);
		p->p = pcap_open_live(interface, snaplen, promisc, 0, errbuf);
		if (!p->p) {
			dprint("Error when opening interface %s : %s\n", interface, errbuf);
			return POM_ERR;
		}
	} else {
		dprint("Invalid input mode\n");
		return POM_ERR;
	}

	switch (pcap_datalink(p->p)) {
		case DLT_EN10MB:
			dprint("PCAP output type is ethernet\n");
			p->output_layer = (*i_functions->match_register) ("ethernet");
			break;
#ifdef DLT_DOCSIS // this doesn't exits in all libpcap version
		case DLT_DOCSIS:
			dprint("PCAP output type is docsis\n");
			p->output_layer = (*i_functions->match_register) ("docsis");
			break;
#endif
		case DLT_LINUX_SLL:
			dprint("PCAP output type is linux_cooked\n");
			p->output_layer = (*i_functions->match_register) ("linux_cooked");
			break;

		case DLT_RAW:
			dprint("PCAP output type is ipv4\n");
			p->output_layer = (*i_functions->match_register) ("ipv4");
			break;

		default:
			dprint("PCAP output type is undefined\n");
			p->output_layer = (*i_functions->match_register) ("undefined");

	}

	if (strlen(errbuf) > 0)
		dprint("PCAP warning : %s\n", errbuf);
	

	if (p->p)	
		dprint("Pcap opened successfullly\n");
	else {
		dprint("Error while opening pcap input\n");
		return POM_ERR;
	}
	
	return pcap_get_selectable_fd(p->p);
}

int input_read_pcap(struct input *i, struct frame *f) {

	struct input_priv_pcap *p = i->input_priv;
	const u_char *next_pkt;

	struct pcap_pkthdr *phdr;

	int result;
	result = pcap_next_ex(p->p, &phdr, &next_pkt);

	if (result < 0) {
		dprint("Error while reading packet.\n");
		return POM_ERR;
	}

	if (f->bufflen < phdr->caplen) {
		dprint("Please increase your read buffer. Provided %u, needed %u\n", f->bufflen, phdr->caplen);
		phdr->caplen = f->bufflen;
		
	}
	memcpy(f->buff, next_pkt, phdr->caplen);
	memcpy(&f->tv, &phdr->ts, sizeof(struct timeval));

	f->len = phdr->caplen;
	f->first_layer = p->output_layer;

	return POM_OK;
}

int input_close_pcap(struct input *i) {

	struct input_priv_pcap *p = i->input_priv;
	if (!p)
		return POM_ERR;

	if (!p->p)
		return POM_OK;

	struct pcap_stat ps;
	if (!pcap_stats(p->p, &ps)) 
		dprint("0x%02lx; PCAP : Total packet read %u, dropped %u (%.1f%%)\n", (unsigned long) i->input_priv, ps.ps_recv, ps.ps_drop, 100.0 / (ps.ps_recv + ps.ps_drop)  * (float)ps.ps_drop);

	pcap_close(p->p);

	return POM_OK;

}

int input_getcaps_pcap(struct input *i, struct input_caps *ic) {

	struct input_priv_pcap *p = i->input_priv;

	if (!p->p)
		return POM_ERR;

	ic->snaplen = pcap_snapshot(p->p);
	if (i->mode == mode_file) 
		ic->is_live = 0;
	else
		ic->is_live = 1;

	return POM_OK;

}


