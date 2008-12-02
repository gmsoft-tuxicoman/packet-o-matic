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
#include "ptype_uint64.h"
#include "ptype_bool.h"
#include "ptype_interval.h"

static struct target_mode *mode_default, *mode_split;

int target_register_pcap(struct target_reg *r) {

	r->init = target_init_pcap;
	r->open = target_open_pcap;
	r->process = target_process_pcap;
	r->close = target_close_pcap;
	r->cleanup = target_cleanup_pcap;

	mode_default = target_register_mode(r->type, "default", "Dump all the packets into a PCAP file");
	mode_split = target_register_mode(r->type, "split", "Dump all packets into multiple PCAP files");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "filename", "dump.cap", "Filename to save packets to");
	target_register_param(mode_default, "snaplen", "1522", "Maximum size of saved packets");
	target_register_param(mode_default, "layer", "ethernet", "Type of layer to capture. Either ethernet, linux_cooked, docsis or ipv4");
	target_register_param(mode_default, "unbuffered", "no", "Write each packet to the output file directly without using a buffer");

	target_register_param(mode_split, "prefix", "dump", "Prefix of output files to save packets to");
	target_register_param(mode_split, "snaplen", "1522", "Maximum size of saved packets");
	target_register_param(mode_split, "layer", "ethernet", "Type of layer to capture. Either ethernet, linux_cooked, docsis or ipv4");
	target_register_param(mode_split, "split_size", "0", "Split when reaching this size");
	target_register_param(mode_split, "split_packets", "0", "Split when reaching this number of packets");
	target_register_param(mode_split, "split_interval", "0", "Split when reaching this number of seconds");
	target_register_param(mode_split, "unbuffered", "no", "Write each packet to the output file directly without using a buffer");

	return POM_OK;

}

static int target_init_pcap(struct target *t) {

	struct target_priv_pcap *priv = malloc(sizeof(struct target_priv_pcap));
	memset(priv, 0, sizeof(struct target_priv_pcap));
	t->target_priv = priv;

	priv->filename = ptype_alloc("string", NULL);
	priv->snaplen = ptype_alloc("uint16", "bytes");
	priv->layer = ptype_alloc("string", NULL);
	priv->unbuffered = ptype_alloc("bool", NULL);

	priv->split_prefix = ptype_alloc("string", NULL);
	priv->split_size = ptype_alloc("uint64", "bytes");
	priv->split_size->print_mode = PTYPE_UINT64_PRINT_HUMAN_1024;
	priv->split_packets = ptype_alloc("uint64", "packets");
	priv->split_packets->print_mode = PTYPE_UINT64_PRINT_HUMAN;
	priv->split_interval = ptype_alloc("interval", NULL);

	if (!priv->filename ||
		!priv->snaplen ||
		!priv->layer ||
		!priv->unbuffered ||
		!priv->split_prefix ||
		!priv->split_size ||
		!priv->split_packets ||
		!priv->split_interval) {
		target_cleanup_pcap(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "filename", priv->filename);
	target_register_param_value(t, mode_default, "snaplen", priv->snaplen);
	target_register_param_value(t, mode_default, "layer", priv->layer);
	target_register_param_value(t, mode_default, "unbuffered", priv->unbuffered);
	
	target_register_param_value(t, mode_split, "prefix", priv->split_prefix);
	target_register_param_value(t, mode_split, "snaplen", priv->snaplen);
	target_register_param_value(t, mode_split, "layer", priv->layer);
	target_register_param_value(t, mode_split, "unbuffered", priv->unbuffered);
	target_register_param_value(t, mode_split, "split_size", priv->split_size);
	target_register_param_value(t, mode_split, "split_packets", priv->split_packets);
	target_register_param_value(t, mode_split, "split_interval", priv->split_interval);

	return POM_OK;
}

static int target_cleanup_pcap(struct target *t) {

	struct target_priv_pcap *priv = t->target_priv;

	if (priv) {
		ptype_cleanup(priv->filename);
		ptype_cleanup(priv->snaplen);
		ptype_cleanup(priv->layer);
		ptype_cleanup(priv->unbuffered);

		ptype_cleanup(priv->split_prefix);
		ptype_cleanup(priv->split_size);
		ptype_cleanup(priv->split_packets);
		ptype_cleanup(priv->split_interval);

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

	char *filename = NULL;

	if (t->mode == mode_split) {
		char my_name[NAME_MAX];
		snprintf(my_name, NAME_MAX - 1, "%s_%05lu.cap", PTYPE_STRING_GETVAL(priv->split_prefix), priv->split_index);
		filename = my_name;
	} else {
		filename = PTYPE_STRING_GETVAL(priv->filename);
	}

	priv->pdump = pcap_dump_open(priv->p, filename);
	if (!priv->pdump) {
		pom_log(POM_LOG_ERR "Unable to open pcap file %s for writing !", filename);
		pcap_close(priv->p);
		return POM_ERR;
	}

	if (PTYPE_INTERVAL_GETVAL(priv->split_interval) > 0)
		priv->split_time = time(NULL) + PTYPE_INTERVAL_GETVAL(priv->split_interval);

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


	if (t->mode == mode_split) {
		// Let's see if we have to open the next file

		int next = 0;
		time_t now;
		time(&now);
		if (PTYPE_UINT64_GETVAL(priv->split_size) > 0 && priv->cur_size + sizeof(struct pcap_pkthdr) + phdr.caplen > PTYPE_UINT64_GETVAL(priv->split_size)) {
			next = 1;
		} else if (PTYPE_UINT64_GETVAL(priv->split_packets) > 0 && priv->cur_packets_num >= PTYPE_UINT64_GETVAL(priv->split_packets)) {
			next = 2;
		} else if (PTYPE_INTERVAL_GETVAL(priv->split_interval) > 0 && priv->split_time < now) {
			next = 3;
		}


		if (next) {
			char filename[NAME_MAX];

			pcap_dump_close(priv->pdump);
			priv->split_index++;

			snprintf(filename, NAME_MAX - 1, "%s_%05lu.cap", PTYPE_STRING_GETVAL(priv->split_prefix), priv->split_index);
			priv->pdump = pcap_dump_open(priv->p, filename);
			if (!priv->pdump) {
				pom_log(POM_LOG_ERR "Unable to open pcap file %s for writing !", filename);
				pcap_close(priv->p);
				priv->p = NULL;
				return POM_ERR;
			}

			priv->split_time = now + PTYPE_INTERVAL_GETVAL(priv->split_interval);
			priv->tot_size += priv->cur_size;
			priv->cur_size = 0;
			priv->tot_packets_num += priv->cur_packets_num;
			priv->cur_packets_num = 0;

			switch (next) {
				case 1:
					pom_log("Size limit reached, continuing with file %s", filename);
					break;
				case 2:
					pom_log("Packet number limit reached, continuing with file %s", filename);
					break;
				case 3:
					pom_log("Elapsed time limit reached, continuing with file %s", filename);
					break;
			}

		}
		
	}

	pcap_dump((u_char*)priv->pdump, &phdr, f->buff + start);



	if (PTYPE_BOOL_GETVAL(priv->unbuffered)) 
		pcap_dump_flush(priv->pdump);

	priv->cur_size = pcap_dump_ftell(priv->pdump);
	priv->cur_packets_num++;

	pom_log(POM_LOG_TSHOOT "Packet saved (%lu bytes )!", priv->tot_size, len);

	return POM_OK;
};

static int target_close_pcap(struct target *t) {
	
	struct target_priv_pcap *priv = t->target_priv;

	if (!t->target_priv)
		return POM_ERR;

	priv->tot_packets_num += priv->cur_packets_num;
	priv->cur_packets_num = 0;
	priv->tot_size += priv->cur_size;
	priv->cur_size = 0;
	priv->split_index++;

	if (t->mode == mode_split)
		pom_log("Saved %lu packets and %lu bytes in %lu files", priv->tot_packets_num, priv->tot_size, priv->split_index);
	else
		pom_log("Saved %lu packets and %lu bytes", priv->tot_packets_num, priv->tot_size);

	if (priv->pdump) {
		pcap_dump_close(priv->pdump);
		priv->pdump = NULL;
	}

	if (priv->p) {
		pcap_close(priv->p);
		priv->p = NULL;
	}
	return POM_OK;
};


