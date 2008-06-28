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

#include "target_pcap.h"
#include "ptype_string.h"
#include "ptype_uint16.h"
#include "ptype_bool.h"

static struct target_mode *mode_default;

int target_register_pcap(struct target_reg *r) {

	r->init = target_init_pcap;
	r->open = target_open_pcap;
	r->process = target_process_pcap;
	r->close = target_close_pcap;
	r->cleanup = target_cleanup_pcap;

	mode_default = target_register_mode(r->type, "default", "Dump all the packets into a PCAP file");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "filename", "dump.cap", "Filename to save packets to");
	target_register_param(mode_default, "snaplen", "1522", "Maximum size of saved packets");
	target_register_param(mode_default, "layer", "ethernet", "Type of layer to capture. Either ethernet, linux_cooked, docsis or ipv4");
	target_register_param(mode_default, "unbuffered", "no", "Write each packet to the output file directly without using a buffer");


	return POM_OK;

}

static int target_init_pcap(struct target *t) {

	struct target_priv_pcap *priv = malloc(sizeof(struct target_priv_pcap));
	memset(priv, 0, sizeof(struct target_priv_pcap));
	t->target_priv = priv;

	priv->filename = ptype_alloc("string", NULL);
	priv->snaplen = ptype_alloc("uint16", NULL);
	priv->layer = ptype_alloc("string", NULL);
	priv->unbuffered = ptype_alloc("bool", NULL);

	if (!priv->filename || !priv->snaplen || !priv->layer || !priv->unbuffered) {
		target_cleanup_pcap(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "filename", priv->filename);
	target_register_param_value(t, mode_default, "snaplen", priv->snaplen);
	target_register_param_value(t, mode_default, "layer", priv->layer);
	target_register_param_value(t, mode_default, "unbuffered", priv->unbuffered);
	

	return POM_OK;
}

static int target_cleanup_pcap(struct target *t) {

	struct target_priv_pcap *priv = t->target_priv;

	if (priv) {
		ptype_cleanup(priv->filename);
		ptype_cleanup(priv->snaplen);
		ptype_cleanup(priv->layer);
		ptype_cleanup(priv->unbuffered);
		free(priv);
	}

	return POM_OK;
}


static int target_open_pcap(struct target *t) {

	struct target_priv_pcap *priv = t->target_priv;


	priv->last_layer_type = -1;
	int snaplen = PTYPE_UINT16_GETVAL(priv->snaplen);

	if (!strcasecmp("ethernet", PTYPE_STRING_GETVAL(priv->layer))) {
		priv->p = pcap_open_dead(DLT_EN10MB, snaplen);
		priv->last_layer_type = match_register("ethernet");
	} else if (!strcasecmp("linux_cooked", PTYPE_STRING_GETVAL(priv->layer))) {
		priv->p = pcap_open_dead(DLT_LINUX_SLL, snaplen);
		priv->last_layer_type = match_register("linux_cooked");
	} else if (!strcasecmp("ipv4", PTYPE_STRING_GETVAL(priv->layer))) {
		priv->p = pcap_open_dead(DLT_RAW, snaplen);
		priv->last_layer_type = match_register("ipv4");
#ifdef DLT_DOCSIS
	} else if (!strcasecmp("docsis", PTYPE_STRING_GETVAL(priv->layer))) {
		priv->p = pcap_open_dead(DLT_DOCSIS, snaplen);
		priv->last_layer_type = match_register("docsis");
#endif
	} else {
		pom_log(POM_LOG_ERR "Pcap : error: no supported header found.");
		return POM_ERR;
	}

	if (!priv->p) {
		pom_log(POM_LOG_ERR "Unable to open pcap !");
		return POM_ERR;
	}

	priv->pdump = pcap_dump_open(priv->p, PTYPE_STRING_GETVAL(priv->filename));
	if (!priv->pdump) {
		pom_log(POM_LOG_ERR "Unable to open pcap dumper !");
		return POM_ERR;
	}

	return POM_OK;	

}


static int target_process_pcap(struct target *t, struct frame *f) {

	struct target_priv_pcap *priv = t->target_priv;
	
	if (!priv->pdump) {
		pom_log(POM_LOG_ERR "Error, pcap target not opened !");
		return POM_ERR;
	}
	
	int start = layer_find_start(f->l, priv->last_layer_type);

	if (start == POM_ERR) {

		pom_log(POM_LOG_WARN "target_pcap: Unable to find the start of the packet. You probably need to set the parameter \"layer\" to \"%s\"", match_get_name(f->l->type));
		return POM_ERR;

	}
	
	
	
	struct pcap_pkthdr phdr;
	
	memcpy(&phdr.ts, &f->tv, sizeof(struct timeval));
	
	unsigned int len = f->len - start;
	phdr.len = len;
	
	if (SNAPLEN > len)
		phdr.caplen = len;
	else
		phdr.caplen = SNAPLEN;
	
	pcap_dump((u_char*)priv->pdump, &phdr, f->buff + start);

	if (PTYPE_BOOL_GETVAL(priv->unbuffered)) 
		pcap_dump_flush(priv->pdump);

	priv->size += len;

	pom_log(POM_LOG_TSHOOT "0x%lx; Packet saved (%u bytes (+%u bytes))!", (unsigned long) priv, priv->size, len);

	return POM_OK;
};

static int target_close_pcap(struct target *t) {
	
	struct target_priv_pcap *priv = t->target_priv;

	if (!t->target_priv)
		return POM_ERR;

	pom_log("0x%lx; PCAP : saved %u bytes", (unsigned long) priv, priv->size);

	pcap_dump_close(priv->pdump);
	priv->pdump = NULL;
	pcap_close(priv->p);
	priv->p = NULL;
	return POM_OK;
};


