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


#include "target_tap.h"
#include "ptype_string.h"
#include "ptype_bool.h"

#include <linux/if_tun.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <net/if.h>
#include <errno.h>

static int match_ethernet_id;

static struct target_mode *mode_default;

static int instance_count = 0;

int target_register_tap(struct target_reg *r) {

	r->init = target_init_tap;
	r->open = target_open_tap;
	r->process = target_process_tap;
	r->close = target_close_tap;
	r->cleanup = target_cleanup_tap;

	match_ethernet_id = match_register("ethernet");

	mode_default = target_register_mode(r->type, "default", "Send packets to a new virtual interface");

	if (!mode_default)
		return POM_ERR;
	
	target_register_param(mode_default, "ifname", "pom", "Interface to create");
	target_register_param(mode_default, "persistent", "no", "Create a persistent interface");


	return POM_OK;

}


static int target_init_tap(struct target *t) {

	if (match_ethernet_id == -1)
		return POM_ERR;

	struct target_priv_tap *priv = malloc(sizeof(struct target_priv_tap));
	memset(priv, 0, sizeof(struct target_priv_tap));

	t->target_priv = priv;

	priv->ifname = ptype_alloc("string", NULL);
	priv->persistent = ptype_alloc("bool", NULL);

	if (!priv->ifname || !priv->persistent) {
		target_cleanup_tap(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "ifname", priv->ifname);
	target_register_param_value(t, mode_default, "persistent", priv->persistent);

	char buff[32];
	snprintf(buff, 31, "pom%u", instance_count);
	PTYPE_STRING_SETVAL(priv->ifname, buff);
	instance_count++;

	return POM_OK;
}

static int target_cleanup_tap(struct target *t) {

	struct target_priv_tap *priv = t->target_priv;

	if (priv) {	
		ptype_cleanup(priv->ifname);
		ptype_cleanup(priv->persistent);
		free(priv);
	}

	return POM_OK;
}


static int target_open_tap(struct target *t) {

	struct target_priv_tap *priv = t->target_priv;

	priv->fd = open("/dev/net/tun", O_RDWR | O_SYNC);
	if (priv->fd < 0) {
		pom_log(POM_LOG_ERR "Failed to open tap device");
		return POM_ERR;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, PTYPE_STRING_GETVAL(priv->ifname), IFNAMSIZ);
	
	if (ioctl(priv->fd, TUNSETIFF, (void *) &ifr) < 0) {
		pom_log(POM_LOG_ERR "Unable to setup tap device %s", PTYPE_STRING_GETVAL(priv->ifname));
		close(priv->fd);
		return POM_ERR;
	}

	if (ioctl(priv->fd, TUNSETPERSIST, PTYPE_BOOL_GETVAL(priv->persistent)) < 0) {
		pom_log(POM_LOG_WARN "Unable to set persistent mode to tap device %s", PTYPE_STRING_GETVAL(priv->ifname));
	}


	return POM_OK;	
}


static int target_process_tap(struct target *t, struct frame *f) {

	struct target_priv_tap *priv = t->target_priv;

	if (priv->fd < 1) {
		pom_log(POM_LOG_ERR "Error, tap target not opened !");
		return POM_ERR;
	}
	
	size_t start = layer_find_start(f->l, match_ethernet_id);

	if (start == POM_ERR) {
		pom_log(POM_LOG_ERR "Unable to find the start of the packet");
		return POM_OK;

	}

	size_t wres = 0, size = f->len - start;

	while (size > 0) {
		wres = write(priv->fd, f->buff + start, size);
		if (wres == -1) {
			char errbuff[256];
			strerror_r(errno, errbuff, sizeof(errbuff) - 1);
			pom_log(POM_LOG_ERR "Error while writing to the tap interface : %s", errbuff);
			return POM_ERR;
		}
		start += wres;
		size -= wres;
	}

	return POM_OK;
}

static int target_close_tap(struct target *t) {
	
	struct target_priv_tap *priv = t->target_priv;

	if (priv->fd != -1)
		close(priv->fd);

	return POM_OK;
}



