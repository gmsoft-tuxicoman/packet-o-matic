
#include <errno.h>

#include "target_inject.h"

// Maximum segment len with ethernet header
#define MAX_SEGMENT_LEN 1518

int match_ethernet_id;

int target_register_inject(struct target_reg *r) {

	r->init = target_init_inject;
	r->open = target_open_inject;
	r->process = target_process_inject;
	r->close = target_close_inject;
	r->cleanup = target_cleanup_inject;


	return 1;

}

int target_cleanup_inject(struct target *t) {

	if (t->target_priv)
		free(t->target_priv);

	return 1;
}


int target_init_inject(struct target *t) {

	match_ethernet_id = (*t->match_register) ("ethernet");
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

int target_open_inject(struct target *t, const char *device) {

	
	struct target_priv_inject *priv = t->target_priv;

	if (!priv) {
		printf("Error, inject target not initialized !\n");
		return 0;
	}

	
	// find out the interface number
	struct ifreq req;
	strcpy(req.ifr_name, device);
	if (ioctl(priv->socket, SIOCGIFINDEX, &req)) {
		dprint("Interface %s not found\n", device);
		return 0;
	}
	dprint("Found interface number %u\n", req.ifr_ifindex);


	// Let's say were to send it
	priv->sal.sll_family = AF_PACKET;
	priv->sal.sll_halen = 6;
	priv->sal.sll_ifindex = req.ifr_ifindex;

	return 1;
}

int target_process_inject(struct target *t, struct rule_node *node, void *frame, unsigned int len) {
	
	struct target_priv_inject *priv = t->target_priv;

	if (!priv->socket) {
		dprint("Error, inject target not opened !\n");
		return 0;
	}
	int start = node_find_header_start(node, match_ethernet_id);
	if (start == -1) {
		dprint("Unable to find the start of the packet\n");
		return 0;
	}

	if (len > MAX_SEGMENT_LEN)
		len = MAX_SEGMENT_LEN;
	
	//memcpy(&priv->sal.sll_addr, frame + 6, 6);
	if(sendto(priv->socket, frame + start, len - start, 0, (struct sockaddr *)&priv->sal, sizeof(priv->sal)) == len) {
		priv->size += len;
		printf("0x%x; Packet injected (%u bytes (+%u bytes))!\n", (unsigned int) priv, priv->size, len);
		return 1;
	}
	
	dprint("Error while injecting packet : %s\n", strerror(errno));
	return 0;

}

int target_close_inject(struct target *t) {

	if (!t->target_priv)
		return 0;

	struct target_priv_inject *priv = t->target_priv;
	close(priv->socket);
	free(priv);
	t->target_priv = NULL;

	dprint("0x%x; INJECT : %u bytes injected\n", (unsigned int) priv, priv->size);
	
	return 1;
}
