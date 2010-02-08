/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2010 Guy Martin <gmsoft@tuxicoman.be>
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


#include <errno.h>

#include "target_inject.h"
#include "ptype_string.h"

// Maximum segment len with ethernet header
#define MAX_SEGMENT_LEN 1518

static int match_ethernet_id;
static struct target_mode *mode_default;

int target_register_inject(struct target_reg *r) {

	r->init = target_init_inject;
	r->open = target_open_inject;
	r->process = target_process_inject;
	r->close = target_close_inject;
	r->cleanup = target_cleanup_inject;

	match_ethernet_id = match_register("ethernet");

	mode_default = target_register_mode(r->type, "default", "Reinject matched packets on the specified interface");
	if (!mode_default)
		return POM_ERR;

	char err[PCAP_ERRBUF_SIZE];
	char *dev = pcap_lookupdev(err);
	if (!dev)
		dev = "none";

	target_register_param(mode_default, "interface", dev, "Where to reinject packets to");

	return POM_OK;

}


static int target_init_inject(struct target *t) {

	if (match_ethernet_id == -1)
		return POM_ERR;

	struct target_priv_inject *priv = malloc(sizeof(struct target_priv_inject));
	memset(priv, 0, sizeof(struct target_priv_inject));
	t->target_priv = priv;

	priv->iface = ptype_alloc("string", NULL);

	if (!priv->iface) {
		target_cleanup_inject(t);
		return POM_ERR;
	}
	
	target_register_param_value(t, mode_default, "interface", priv->iface);

	return POM_OK;
}

static int target_cleanup_inject(struct target *t) {

	struct target_priv_inject *priv = t->target_priv;

	if (priv) {
		ptype_cleanup(priv->iface);
		free(priv);
	}

	return POM_OK;
}

static int target_open_inject(struct target *t) {

	
	struct target_priv_inject *priv = t->target_priv;

	if (!priv) {
		pom_log(POM_LOG_ERR "Error, inject target not initialized !");
		return POM_ERR;
	}

	char errbuf[PCAP_ERRBUF_SIZE];

	int snaplen = 2000; // This param won't be used anyway
	priv->p = pcap_open_live(PTYPE_STRING_GETVAL(priv->iface), snaplen, 0, 0, errbuf);
	if (!priv->p) {
		pom_log(POM_LOG_ERR "Error, cannot open interface %s with pcap : %s", PTYPE_STRING_GETVAL(priv->iface), errbuf);
		return POM_ERR;
	}
	pom_log(POM_LOG_DEBUG "Interface %s opened for injection", PTYPE_STRING_GETVAL(priv->iface));


	return POM_OK;
}

static int target_process_inject(struct target *t, struct frame *f) {
	
	struct target_priv_inject *priv = t->target_priv;

	if (!priv->p) {
		pom_log(POM_LOG_ERR "Error, pcap not initialized !");
		return POM_ERR;
	}
	int start = layer_find_start(f->l, match_ethernet_id);
	if (start == POM_ERR) {
		pom_log(POM_LOG_ERR "Unable to find the start of the packet");
		return POM_ERR;
	}

	unsigned int len = f->len;

	if (len > MAX_SEGMENT_LEN)
		len = MAX_SEGMENT_LEN;
	
	if (pcap_inject(priv->p, f->buff + start, len - start) != -1) {
		
		pom_log(POM_LOG_DEBUG "Packet injected (+%u bytes)", len);
		return POM_OK;
	} 

	pom_log(POM_LOG_ERR "Error while injecting packet : %s", pcap_geterr(priv->p));
	return POM_ERR;

}

static int target_close_inject(struct target *t) {

	if (!t->target_priv)
		return POM_ERR;

	struct target_priv_inject *priv = t->target_priv;

	char size_str[16], count_str[16];
	perf_item_val_get_human_1024(t->perf_bytes, size_str, sizeof(size_str) - 1);
	perf_item_val_get_human(t->perf_pkts, count_str, sizeof(count_str) - 1);

	pom_log("%s bytes injected in %s packets", size_str, count_str);

	if (priv->p) 
		pcap_close(priv->p);
	
	return POM_OK;
}
