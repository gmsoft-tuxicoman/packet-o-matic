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


#include "target_tap.h"

#define PARAMS_NUM 1

char *target_tap_params[PARAMS_NUM][3] = {
	{ "ifname", "pom0", "interface to send packets to"},
};

int match_ethernet_id;

struct target_functions *tg_functions;

int target_register_tap(struct target_reg *r, struct target_functions *tg_funcs) {

	copy_params(r->params_name, target_tap_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_tap_params, 2, PARAMS_NUM);

	r->init = target_init_tap;
	r->open = target_open_tap;
	r->process = target_process_tap;
	r->close = target_close_tap;
	r->cleanup = target_cleanup_tap;

	tg_functions = tg_funcs;

	return 1;

}

int target_cleanup_tap(struct target *t) {

	clean_params(t->params_value, PARAMS_NUM);

	if (t->target_priv)
		free(t->target_priv);

	return 1;
}


int target_init_tap(struct target *t) {

	copy_params(t->params_value, target_tap_params, 1, PARAMS_NUM);

	match_ethernet_id = (*tg_functions->match_register) ("ethernet");
	if (match_ethernet_id == -1)
		return 0;

	struct target_priv_tap *priv = malloc(sizeof(struct target_priv_tap));
	bzero(priv, sizeof(struct target_priv_tap));

	t->target_priv = priv;
	

	return 1;
}


int target_open_tap(struct target *t) {

	struct target_priv_tap *priv = t->target_priv;

	priv->fd = open("/dev/net/tun", O_RDWR | O_SYNC);
	if (priv->fd < 0) {
		dprint("Failed to open tap device\n");
		return 0;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, t->params_value[0], IFNAMSIZ);
	
	if (ioctl(priv->fd, TUNSETIFF, (void *) &ifr) < 0 ) {
		dprint("Unable to setup tap device\n");
		close(priv->fd);
		return 0;
	}


	return 1;	
}


int target_process_tap(struct target *t, struct layer *l, void *frame, unsigned int len, struct conntrack_entry *ce) {

	struct target_priv_tap *priv = t->target_priv;

	if (priv->fd < 1) {
		dprint("Error, tap target not opened !\n");
		return 0;
	}
	
	int start = layer_find_start(l, match_ethernet_id);

	if (start == -1) {
		dprint("Unable to find the start of the packet\n");
		return 0;

	}
	
	frame += start;
	len -= start;

        write(priv->fd, frame + start, len);

	return 1;
};

int target_close_tap(struct target *t) {
	
	struct target_priv_tap *priv = t->target_priv;
	
	close(priv->fd);
	free(priv);
	t->target_priv = NULL;
	return 1;
};



