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

	target_register_param(mode_default, "interface", "eth0", "Where to reinject packets to");

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
		pom_log(POM_LOG_ERR "Error, inject target not initialized !\r\n");
		return POM_ERR;
	}

	char errbuf[LIBNET_ERRBUF_SIZE];

	priv->lc = libnet_init (LIBNET_LINK_ADV, PTYPE_STRING_GETVAL(priv->iface), errbuf);
	if (!priv->lc) {
		pom_log(POM_LOG_ERR "Error, cannot open libnet context: %s\r\n", errbuf);
		return POM_ERR;
	}
	pom_log(POM_LOG_DEBUG "Libnet context initialized for interface %s\r\n", priv->lc->device);


	return POM_OK;
}

static int target_process_inject(struct target *t, struct frame *f) {
	
	struct target_priv_inject *priv = t->target_priv;

	if (!priv->lc) {
		pom_log(POM_LOG_ERR "Error, libnet context not initialized !\r\n");
		return POM_ERR;
	}
	int start = layer_find_start(f->l, match_ethernet_id);
	if (start == POM_ERR) {
		pom_log(POM_LOG_ERR "Unable to find the start of the packet\r\n");
		return POM_ERR;
	}

	unsigned int len = f->len;

	if (len > MAX_SEGMENT_LEN)
		len = MAX_SEGMENT_LEN;
	
	if (libnet_write_link (priv->lc, f->buff + start, len - start) != -1) {
		
		priv->size += len;
		pom_log(POM_LOG_DEBUG"0x%lx; Packet injected (%u bytes (+%u bytes))!\r\n", (unsigned long) priv, priv->size, len);
		return POM_OK;
	}

	pom_log(POM_LOG_ERR "Error while injecting packet : %s\r\n", libnet_geterror(priv->lc));
	return POM_ERR;

}

static int target_close_inject(struct target *t) {

	if (!t->target_priv)
		return POM_ERR;

	struct target_priv_inject *priv = t->target_priv;

	pom_log("0x%lx; INJECT : %u bytes injected\r\n", (unsigned long) priv, priv->size);

	if (priv->lc) {

		/* free libnet context */
		libnet_destroy(priv->lc);
	}
	free(priv);
	t->target_priv = NULL;

	
	return POM_OK;
}
