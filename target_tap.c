
#include "target_tap.h"

int match_ethernet_id;

int target_register_tap(struct target_reg *r) {

	r->init = target_init_tap;
	r->open = target_open_tap;
	r->process = target_process_tap;
	r->close = target_close_tap;
	r->cleanup = target_cleanup_tap;


	return 1;

}

int target_cleanup_tap(struct target *t) {

	if (t->target_priv)
		free(t->target_priv);

	return 1;
}


int target_init_tap(struct target *t) {

	match_ethernet_id = (*t->match_register) ("ethernet");
	if (match_ethernet_id == -1)
		return 0;

	struct target_priv_tap *priv = malloc(sizeof(struct target_priv_tap));
	bzero(priv, sizeof(struct target_priv_tap));

	t->target_priv = priv;
	

	return 1;
}


int target_open_tap(struct target *t, const char *devname) {

	struct target_priv_tap *priv = t->target_priv;

	priv->fd = open("/dev/net/tun", O_RDWR | O_SYNC);
	if (priv->fd < 0) {
		dprint("Failed to open tap device\n");
		return 0;
	}

	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, devname, IFNAMSIZ);
	
	if (ioctl(priv->fd, TUNSETIFF, (void *) &ifr) < 0 ) {
		dprint("Unable to setup tap device\n");
		close(priv->fd);
		return 0;
	}


	return 1;	
}


int target_process_tap(struct target *t, struct rule_node *node, void *frame, unsigned int len) {

	struct target_priv_tap *priv = t->target_priv;

	if (priv->fd < 1) {
		dprint("Error, tap target not opened !\n");
		return 0;
	}
	
	int start = node_find_header_start(node, match_ethernet_id);

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



