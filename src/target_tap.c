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


#include "target_tap.h"
#include "ptype_string.h"


int match_ethernet_id;

struct target_functions *tf;
struct target_mode *mode_default;

int target_register_tap(struct target_reg *r, struct target_functions *tg_funcs) {

	r->init = target_init_tap;
	r->open = target_open_tap;
	r->process = target_process_tap;
	r->close = target_close_tap;
	r->cleanup = target_cleanup_tap;

	tf = tg_funcs;

	match_ethernet_id = (*tf->match_register) ("ethernet");

	mode_default = (*tg_funcs->register_mode) (r->type, "default", "Send packets to a new virtual interface");

	if (!mode_default)
		return POM_ERR;
	
	(*tg_funcs->register_param) (mode_default, "ifname", "pom0", "Interface to create");


	return POM_OK;

}


int target_init_tap(struct target *t) {

	if (match_ethernet_id == -1)
		return POM_ERR;

	struct target_priv_tap *priv = malloc(sizeof(struct target_priv_tap));
	bzero(priv, sizeof(struct target_priv_tap));

	t->target_priv = priv;

	priv->ifname = (*tf->ptype_alloc) ("string", NULL);

	if (!priv->ifname) {
		target_cleanup_tap(t);
		return POM_ERR;
	}

	(*tf->register_param_value) (t, mode_default, "ifname", priv->ifname);
	

	return POM_OK;
}

int target_cleanup_tap(struct target *t) {

	struct target_priv_tap *priv = t->target_priv;

	if (priv) {	
		(*tf->ptype_cleanup) (priv->ifname);
		free(priv);
	}

	return POM_OK;
}


int target_open_tap(struct target *t) {

	struct target_priv_tap *priv = t->target_priv;

	priv->fd = open("/dev/net/tun", O_RDWR | O_SYNC);
	if (priv->fd < 0) {
		(*tf->pom_log) (POM_LOG_ERR "Failed to open tap device\r\n");
		return POM_ERR;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, PTYPE_STRING_GETVAL(priv->ifname), IFNAMSIZ);
	
	if (ioctl(priv->fd, TUNSETIFF, (void *) &ifr) < 0 ) {
		(*tf->pom_log) (POM_LOG_ERR "Unable to setup tap device\r\n");
		close(priv->fd);
		return POM_ERR;
	}


	return POM_OK;	
}


int target_process_tap(struct target *t, struct frame *f) {

	struct target_priv_tap *priv = t->target_priv;

	if (priv->fd < 1) {
		(*tf->pom_log) (POM_LOG_ERR "Error, tap target not opened !\r\n");
		return POM_ERR;
	}
	
	int start = layer_find_start(f->l, match_ethernet_id);

	if (start == -1) {
		(*tf->pom_log) (POM_LOG_ERR "Unable to find the start of the packet\r\n");
		return POM_OK;

	}

	write(priv->fd, f->buff + start, f->len - start);

	return POM_OK;
};

int target_close_tap(struct target *t) {
	
	struct target_priv_tap *priv = t->target_priv;

	if (priv->fd != -1)
		close(priv->fd);

	return POM_OK;
};



