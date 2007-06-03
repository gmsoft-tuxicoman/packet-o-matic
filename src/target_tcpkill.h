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

#ifndef __TARGET_INJECT_H__
#define __TARGET_INJECT_H__

#include "modules_common.h"
#include "target.h"

#ifdef HAVE_LINUX_IP_SOCKET
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#endif
#include <unistd.h>
#include <string.h>
#include <net/ethernet.h>
#include <libnet.h>

struct target_priv_tcpkill {

	int routed; // 1 if mode is routed
#ifdef HAVE_LINUX_IP_SOCKET
	int socket;
#endif
	char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *lc;
	int ifindex;
	unsigned int severity;
};

int target_init_tcpkill(struct target *t);
int target_open_tcpkill(struct target *t);
int target_process_tcpkill(struct target *t, struct frame *f);
int target_close_tcpkill(struct target *t);
int target_cleanup_tcpkill(struct target *t);

#endif
