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


#include <errno.h>

#include "target_inject.h"

// Maximum segment len with ethernet header
#define MAX_SEGMENT_LEN 1518


#define PARAMS_NUM 1

char *target_inject_params[PARAMS_NUM][3] = {
	{ "interface", "eth0", "interface to inject packets on"},
};

int match_ethernet_id;
struct target_functions *tg_functions;

int target_register_inject(struct target_reg *r, struct target_functions *tg_funcs) {

	copy_params(r->params_name, target_inject_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_inject_params, 2, PARAMS_NUM);


	r->init = target_init_inject;
	r->open = target_open_inject;
	r->process = target_process_inject;
	r->close = target_close_inject;
	r->cleanup = target_cleanup_inject;

	tg_functions = tg_funcs;


	return 1;

}

int target_cleanup_inject(struct target *t) {

	clean_params(t->params_value, PARAMS_NUM);

	if (t->target_priv)
		free(t->target_priv);

	return 1;
}


int target_init_inject(struct target *t) {

	copy_params(t->params_value, target_inject_params, 1, PARAMS_NUM);


	match_ethernet_id = (*tg_functions->match_register) ("ethernet");
	if (match_ethernet_id == -1)
		return 0;

	struct target_priv_inject *priv = malloc(sizeof(struct target_priv_inject));
	bzero(priv, sizeof(struct target_priv_inject));

	priv->socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if (priv->socket == -1)
		return 0;

	t->target_priv = priv;
	
	
	
	return 1;
}

int target_open_inject(struct target *t) {

	
	struct target_priv_inject *priv = t->target_priv;

	if (!priv) {
		dprint("Error, inject target not initialized !\n");
		return 0;
	}

	
	// find out the interface number
	struct ifreq req;
	strcpy(req.ifr_name, t->params_value[0]);
	if (ioctl(priv->socket, SIOCGIFINDEX, &req)) {
		dprint("Interface %s not found\n", t->params_value[0]);
		return 0;
	}
	dprint("Found interface number %u\n", req.ifr_ifindex);


	// Let's say were to send it
	priv->sal.sll_family = AF_PACKET;
	priv->sal.sll_halen = 6;
	priv->sal.sll_ifindex = req.ifr_ifindex;

	return 1;
}

int target_process_inject(struct target *t, struct layer *l, void *frame, unsigned int len, struct conntrack_entry *ce) {
	
	struct target_priv_inject *priv = t->target_priv;

	if (!priv->socket) {
		dprint("Error, inject target not opened !\n");
		return 0;
	}
	int start = layer_find_start(l, match_ethernet_id);
	if (start == -1) {
		dprint("Unable to find the start of the packet\n");
		return 0;
	}

	if (len > MAX_SEGMENT_LEN)
		len = MAX_SEGMENT_LEN;
	
	//memcpy(&priv->sal.sll_addr, frame + 6, 6);
	if(sendto(priv->socket, frame + start, len - start, 0, (struct sockaddr *)&priv->sal, sizeof(priv->sal)) == len) {
		priv->size += len;
		dprint("0x%lx; Packet injected (%u bytes (+%u bytes))!\n", (unsigned long) priv, priv->size, len);
		return 1;
	}
	
	dprint("Error while injecting packet : %s\n", strerror(errno));
	return 0;

}

int target_close_inject(struct target *t) {

	if (!t->target_priv)
		return 0;

	struct target_priv_inject *priv = t->target_priv;

	dprint("0x%lx; INJECT : %u bytes injected\n", (unsigned long) priv, priv->size);

	close(priv->socket);
	free(priv);
	t->target_priv = NULL;

	
	return 1;
}