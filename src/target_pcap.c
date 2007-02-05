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


#include "target_pcap.h"

#define PARAMS_NUM 1
char *target_pcap_params[PARAMS_NUM][3] = {
	{ "filename", "dump.cap", "filename to save packets to"},
};

int match_ethernet_id;

struct target_functions *tg_functions;

int target_register_pcap(struct target_reg *r, struct target_functions *tg_funcs) {

	copy_params(r->params_name, target_pcap_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_pcap_params, 2, PARAMS_NUM);

	r->init = target_init_pcap;
	r->open = target_open_pcap;
	r->process = target_process_pcap;
	r->close = target_close_pcap;
	r->cleanup = target_cleanup_pcap;

	tg_functions = tg_funcs;

	return 1;

}

int target_cleanup_pcap(struct target *t) {

	clean_params(t->params_value, PARAMS_NUM);

	if (t->target_priv)
		free(t->target_priv);

	return 1;
}

int target_init_pcap(struct target *t) {

	copy_params(t->params_value, target_pcap_params, 1, PARAMS_NUM);

	match_ethernet_id = (*tg_functions->match_register) ("ethernet");
	if (match_ethernet_id == -1)
		return 0;
	struct target_priv_pcap *priv = malloc(sizeof(struct target_priv_pcap));
	bzero(priv, sizeof(struct target_priv_pcap));

	// FIXME: for now we only handle ethernet packets
	priv->p = pcap_open_dead(DLT_EN10MB, SNAPLEN);
	if (!priv->p) {
		dprint("Unable to open pcap !\n");
		return 0;
	}

	t->target_priv = priv;
	

	return 1;
}


int target_open_pcap(struct target *t) {

	struct target_priv_pcap *priv = t->target_priv;

	if (!priv->p) {
		dprint("Target pcap not initialized !\n");
		return 0;
	}
	
	priv->pdump = pcap_dump_open(priv->p, t->params_value[0]);
	if (!priv->pdump) {
		dprint("Unable to open pcap dumper !\n");
		return 0;
	}

	return 1;	

}


int target_process_pcap(struct target *t, struct layer *l, void *frame, unsigned int len, struct conntrack_entry *ce) {

	struct target_priv_pcap *priv = t->target_priv;
	
	if (!priv->pdump) {
		dprint("Error, pcap target not opened !\n");
		return 0;
	}
	
	int start = layer_find_start(l, match_ethernet_id);

	if (start == -1) {
		dprint("Unable to find the start of the packet\n");
		return 0;

	}
	
	frame += start;
	len -= start;
	
	struct pcap_pkthdr phdr;
	
	gettimeofday(&phdr.ts, NULL);
	
	phdr.len = len;
	
	if (SNAPLEN > len)
		phdr.caplen = len;
	 else
		phdr.caplen = SNAPLEN;
	
	pcap_dump((u_char*)priv->pdump, &phdr, frame);
	//pcap_dump_flush(priv->pdump);

	priv->size += len;

	ndprint("0x%lx; Packet saved (%u bytes (+%u bytes))!\n", (unsigned long) priv, priv->size, len);

	return 1;
};

int target_close_pcap(struct target *t) {
	
	struct target_priv_pcap *priv = t->target_priv;

	if (!t->target_priv)
		return 0;

	dprint("0x%lx; PCAP : saved %u bytes\n", (unsigned long) priv, priv->size);
	
	pcap_dump_close(priv->pdump);
	pcap_close(priv->p);
	free(priv);
	t->target_priv = NULL;
	return 1;
};


