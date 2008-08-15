/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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

static struct input_mode *mode_interface, *mode_file;
static struct ptype *p_filename, *p_interface, *p_snaplen, *p_promisc, *p_filter;

int input_register_pcap(struct input_reg *r) {

	r->init = input_init_pcap;
	r->open = input_open_pcap;
	r->read = input_read_pcap;
	r->close = input_close_pcap;
	r->cleanup = input_cleanup_pcap;
	r->getcaps = input_getcaps_pcap;
	r->unregister = input_unregister_pcap;
	r->interrupt = input_interrupt_pcap;

	mode_interface = input_register_mode(r->type, "interface", "Read packets from an interface");
	mode_file = input_register_mode(r->type, "file", "Read packets from a pcap file");

	if (!mode_interface || !mode_file)
		return POM_ERR;
	
	p_filename = ptype_alloc("string", NULL);
	p_interface = ptype_alloc("string", NULL);
	p_snaplen = ptype_alloc("uint16", "bytes");
	p_promisc = ptype_alloc("bool", NULL);
	p_filter = ptype_alloc("string", NULL);

	if (!p_filename || !p_interface || !p_snaplen || !p_promisc || !p_filter) {
		input_unregister_pcap(r);
		return POM_ERR;
	}

	char err[PCAP_ERRBUF_SIZE];
	char *dev = pcap_lookupdev(err);
	if (!dev)
		dev = "none";

	input_register_param(mode_interface, "interface", dev, p_interface, "Interface to listen from");
	input_register_param(mode_interface, "snaplen", "1522", p_snaplen, "Snaplen");
	input_register_param(mode_interface, "promisc", "no", p_promisc, "Promiscuous");
	input_register_param(mode_interface, "filter", "", p_filter, "BFP filter");

	input_register_param(mode_file, "file", "dump.cap", p_filename, "PCAP file");
	input_register_param(mode_file, "filter", "", p_filter, "BFP filter");

	return POM_OK;
}


static int input_init_pcap(struct input *i) {

	i->input_priv = malloc(sizeof(struct input_priv_pcap));
	memset(i->input_priv, 0, sizeof(struct input_priv_pcap));

	return POM_OK;

}

static int input_cleanup_pcap(struct input *i) {

	if (i->input_priv)
		free(i->input_priv);

	return POM_OK;

}

static int input_unregister_pcap(struct input_reg *r) {

	ptype_cleanup(p_interface);
	ptype_cleanup(p_snaplen);
	ptype_cleanup(p_promisc);
	ptype_cleanup(p_filename);
	ptype_cleanup(p_filter);
	return POM_OK;
}

static int input_open_pcap(struct input *i) {


	struct input_priv_pcap *p = i->input_priv;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	errbuf[0] = 0;

	if (i->mode == mode_file) {
		char *filename = PTYPE_STRING_GETVAL(p_filename);
		p->p = pcap_open_offline(filename, errbuf);
		if (!p->p) {
			pom_log(POM_LOG_ERR "Error opening file %s for reading", filename);
			return POM_ERR;
		}
	} else if (i->mode == mode_interface) {
		char *interface = PTYPE_STRING_GETVAL(p_interface);
		int snaplen = PTYPE_UINT16_GETVAL(p_snaplen);
		int promisc = PTYPE_BOOL_GETVAL(p_promisc);
		if (snaplen < 64)
			snaplen = 64;
		pom_log("Opening interface %s with a snaplen of %u", interface, snaplen);
		p->p = pcap_open_live(interface, snaplen, promisc, 0, errbuf);
		if (!p->p) {
			pom_log(POM_LOG_ERR "Error when opening interface %s : %s", interface, errbuf);
			return POM_ERR;
		}
	} else {
		pom_log(POM_LOG_ERR "Invalid input mode");
		return POM_ERR;
	}

	switch (pcap_datalink(p->p)) {
		case DLT_EN10MB:
			pom_log("PCAP output type is ethernet");
			p->output_layer = match_register("ethernet");
			break;
#ifdef DLT_DOCSIS // this doesn't exits in all libpcap version
		case DLT_DOCSIS:
			pom_log("PCAP output type is docsis");
			p->output_layer = match_register("docsis");
			break;
#endif
		case DLT_LINUX_SLL:
			pom_log("PCAP output type is linux_cooked");
			p->output_layer = match_register("linux_cooked");
			break;

		case DLT_RAW:
			pom_log("PCAP output type is ipv4");
			p->output_layer = match_register("ipv4");
			break;

		default:
			pom_log("PCAP output type is undefined");
			p->output_layer = match_register("undefined");

	}

	if (strlen(errbuf) > 0)
		pom_log(POM_LOG_WARN "PCAP warning : %s", errbuf);
	

	if (p->p)	
		pom_log("PCAP opened successfullly");
	else {
		pom_log(POM_LOG_ERR "Error while opening pcap input");
		return POM_ERR;
	}

	if (strlen(PTYPE_STRING_GETVAL(p_filter)) > 0) {
	
		if (pcap_compile(p->p, &p->fp, PTYPE_STRING_GETVAL(p_filter), 1, 0) == -1) {

			pom_log(POM_LOG_ERR "Unable to compile BFP filter \"%s\"", PTYPE_STRING_GETVAL(p_filter));
			pcap_close(p->p);
			return POM_ERR;
		
		}

		if (pcap_setfilter(p->p, &p->fp) == -1) {
			pom_log(POM_LOG_ERR "Unable to set the BFP filter \"%s\"", PTYPE_STRING_GETVAL(p_filter));
			pcap_freecode(&p->fp);
			pcap_close(p->p);
			return POM_ERR;
		}

	}

	p->packets_read = 0;

	return POM_OK;
}

static int input_read_pcap(struct input *i, struct frame *f) {

	struct input_priv_pcap *p = i->input_priv;
	const u_char *next_pkt;

	struct pcap_pkthdr *phdr;

	int result;
	result = pcap_next_ex(p->p, &phdr, &next_pkt);

	if (result == -2) { // End of file
		input_close(i);
		return POM_OK;
	}

	if (result < 0) {
		pom_log(POM_LOG_ERR "Error while reading packet.");
		return POM_ERR;
	}

	if (result == 0) {
		f->len = 0;
		return POM_OK;
	}

	if (f->bufflen < phdr->caplen) {
		pom_log(POM_LOG_WARN "Please increase your read buffer. Provided %u, needed %u", f->bufflen, phdr->caplen);
		phdr->caplen = f->bufflen;
		
	}
	memcpy(f->buff, next_pkt, phdr->caplen);
	memcpy(&f->tv, &phdr->ts, sizeof(struct timeval));

	f->len = phdr->caplen;
	f->first_layer = p->output_layer;

	p->packets_read++;

	return POM_OK;
}

static int input_close_pcap(struct input *i) {

	struct input_priv_pcap *p = i->input_priv;
	if (!p)
		return POM_ERR;

	if (!p->p)
		return POM_OK;

	pcap_freecode(&p->fp);

	struct pcap_stat ps;
	if (!pcap_stats(p->p, &ps)) 
		pom_log("Total packet read %u, dropped %u (%.1f%%)", (unsigned long) i->input_priv, ps.ps_recv, ps.ps_drop, 100.0 / (ps.ps_recv + ps.ps_drop)  * (float)ps.ps_drop);
	else
		pom_log("Total packet read %lu", p->packets_read);

	pcap_close(p->p);

	return POM_OK;

}

static int input_getcaps_pcap(struct input *i, struct input_caps *ic) {

	struct input_priv_pcap *p = i->input_priv;

	if (!p->p)
		return POM_ERR;

	ic->snaplen = pcap_snapshot(p->p);
	if (i->mode == mode_file) 
		ic->is_live = 0;
	else
		ic->is_live = 1;

	switch (pcap_datalink(p->p)) {
		case DLT_EN10MB: // ethernet is 14 bytes long
			ic->buff_align_offset = 2;
			break;
		default: 
			ic->buff_align_offset = 0;
	}

	return POM_OK;

}

static int input_interrupt_pcap(struct input *i) {

	struct input_priv_pcap *p = i->input_priv;

	if (!p || !p->p)
		return POM_ERR;

	pcap_breakloop(p->p);
	return POM_OK;

}

