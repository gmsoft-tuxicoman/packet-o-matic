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

#include "target_tcpkill.h"
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>


#ifdef HAVE_LINUX_IP_SOCKET
#define PARAMS_NUM 3
#else
#define PARAMS_NUM 2
#endif

int cksum(uint16_t *addr, int len)
{
	int sum;
	uint16_t last_byte;

	sum = 0;
	last_byte = 0;

	while (len > 1)	{
		sum += *addr++;
		len -= 2;
	}
	if (len == 1) {
		*(u_int8_t*)&last_byte = *(u_int8_t*)addr;
		sum += last_byte;
	}

	 return (sum);
}


char *target_tcpkill_params[PARAMS_NUM][3] = {
	{ "severity", "2", "numbers of tcp rst packet by try"},
	{ "interface", "eth0", "interface to send packets to in non routed mode" },
#ifdef HAVE_LINUX_IP_SOCKET
	{ "mode", "routed", "operating mode : 'routed' (default) let linux decide where to send packets to but is IPv4 only. 'normal' send the packet to the specified interface"},
#endif
};

int match_ipv4_id, match_ipv6_id, match_tcp_id, match_ethernet_id;

struct target_functions *tg_functions;

int target_register_tcpkill(struct target_reg *r, struct target_functions *tg_funcs) {

	copy_params(r->params_name, target_tcpkill_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_tcpkill_params, 2, PARAMS_NUM);


	r->init = target_init_tcpkill;
	r->open = target_open_tcpkill;
	r->process = target_process_tcpkill;
	r->close = target_close_tcpkill;
	r->cleanup = target_cleanup_tcpkill;

	tg_functions = tg_funcs;

	match_ipv4_id = (*tg_functions->match_register) ("ipv4");
	match_ipv6_id = (*tg_functions->match_register) ("ipv6");
	match_tcp_id = (*tg_functions->match_register) ("tcp");
	match_ethernet_id = (*tg_functions->match_register) ("ethernet");

	return 1;

}

int target_cleanup_tcpkill(struct target *t) {

	clean_params(t->params_value, PARAMS_NUM);

	if (t->target_priv)
		free(t->target_priv);

	return 1;
}


int target_init_tcpkill(struct target *t) {

	copy_params(t->params_value, target_tcpkill_params, 1, PARAMS_NUM);

	if (match_tcp_id == -1)
		return 0;

	struct target_priv_tcpkill *priv = malloc(sizeof(struct target_priv_tcpkill));
	bzero(priv, sizeof(struct target_priv_tcpkill));

	t->target_priv = priv;
	
	return 1;
}

int target_open_tcpkill(struct target *t) {

	struct target_priv_tcpkill *p = t->target_priv;
	
	if (!p) {
		dprint("Error, tcpkill target not initialized !\n");
		return 0;
	}

	if (sscanf(t->params_value[0], "%u", &p->severity) != 1) {
		dprint("Wrong severity parameter to target_tcpkill !\n");
		p->severity = 2;
	}

#ifdef HAVE_LINUX_IP_SOCKET
	if (!strcmp(t->params_value[2], "routed")) {
		p->routed = 1;

		int one = 1;


		// Open IPv4 socket

		p->socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

		if (p->socket < 0) {
			dprint("Unable to open IPv4 socket to send TCP RST\n");
			return 0;
		}
		if (setsockopt (p->socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0) {
			dprint("Unable to set IP_HDRINCL on IPv4 socket !\n");
			return 0;
		}
	} else {
#endif
		p->lc = libnet_init (LIBNET_LINK_ADV, t->params_value[1], p->errbuf);
	        if (!p->lc) {
			dprint("Error, cannot open libnet context: %s", p->errbuf);
			return 0;
		}
      		dprint("Libnet context initialized for interface %s\n", p->lc->device);
#ifdef HAVE_LINUX_IP_SOCKET
	}
#else
	p->routed = 0; /* we don't have linux' raw packet iface so we can't use routing */
#endif

	return 1;
}

int target_process_tcpkill(struct target *t, struct frame *f) {


	struct target_priv_tcpkill *priv = t->target_priv;


	int ipv4start, ipv6start, tcpstart, i;

	tcpstart = layer_find_start(f->l, match_tcp_id);
	if (tcpstart == -1) {
		dprint("No TCP header found in this packet\n");
		return 0;
	}

	struct tcphdr *shdr = (struct tcphdr*) (f->buff + tcpstart);

	// No need to kill RST or FIN packets
	if ((shdr->th_flags & TH_RST) || (shdr->th_flags & TH_FIN))
		return 0;

	ipv4start = layer_find_start(f->l, match_ipv4_id);
	ipv6start = layer_find_start(f->l, match_ipv6_id);

	// init temp buffer
	unsigned char buffer[1024];
	bzero(buffer, 1024);

	int tcpsum = 0;
	int blen = 0; // Buffer len

#ifdef HAVE_LINUX_IP_SOCKET
	// init sockaddr
	struct sockaddr_storage addr;
	socklen_t addrlen = 0;
	bzero(&addr, sizeof(struct sockaddr_storage));


	// In routed mode, we can only send ipv4 packets. linux API doesn't allow random souce addr for ipv6
	if (priv->routed && ipv4start == -1) {
		dprint("No IPv4 header found in this packet\n");
		return 0;
	}
#endif

	// In normal mode we need at least an ipv6 or ipv4 header
	if (!priv->routed && ipv4start == -1 && ipv6start == -1) {
		dprint("No IPv4 or IPv6 header found in this packet\n");
		return 0;
	}

#ifdef HAVE_LINUX_IP_SOCKET
	// Check if the socket is opened
	if (priv->routed && priv->socket <= 0) {
		dprint("Error, socket not opened. Cannot send TCP RST\n");
		return 0;
	}
#endif

	// In normal mode, we have to include the ethernet header
	if (!priv->routed) {
		int ethernetstart;
		ethernetstart = layer_find_start(f->l, match_ethernet_id);
		if (ethernetstart == -1) {
			dprint("No ethernet header found in this packet\n");
			return 0;
		}
		
		ipv6start = layer_find_start(f->l, match_ipv6_id);

		if (ipv4start == -1 && ipv6start == -1) {
			dprint("Neither IPv4 or IPv6 header found in this packet\n");
			return 0;
		}

		// First copy create the right ethernet header
		
		struct ether_header *dehdr = (struct ether_header*) buffer, *sehdr = (struct ether_header*) (f->buff + ethernetstart);
		memcpy(dehdr->ether_shost, sehdr->ether_dhost, sizeof(dehdr->ether_shost));
		memcpy(dehdr->ether_dhost, sehdr->ether_shost, sizeof(dehdr->ether_dhost));
		dehdr->ether_type = sehdr->ether_type;

		blen = sizeof(struct ether_header);

	}

	// Let's see if we have a IPv4 header. This can only be false in normal mode in case of an IPv6 packet
	if (ipv4start != -1) {

		struct ip *dv4hdr = (struct ip*) (buffer + blen), *sv4hdr = (struct ip*) (f->buff + ipv4start);
	
#ifdef HAVE_LINUX_IP_SOCKET
		if (priv->routed) { // Create the right sockaddr_in in routed mode
			struct sockaddr_in *sin = (struct sockaddr_in *) &addr;
			addrlen = sizeof(struct sockaddr_in);
			sin->sin_family = AF_INET;
			memcpy(&sin->sin_addr, &sv4hdr->ip_src, sizeof(struct in_addr));
			sin->sin_port = shdr->th_sport;
		}
#endif

		dv4hdr->ip_src = sv4hdr->ip_dst;
		dv4hdr->ip_dst = sv4hdr->ip_src;
		if (ipv6start != -1) { // IPv6 in IPv4
			dv4hdr->ip_p = IPPROTO_IPV6;
			dv4hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct ip6_hdr) + sizeof(struct tcphdr));
		} else {
			dv4hdr->ip_p = IPPROTO_TCP;
			dv4hdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
		}
		dv4hdr->ip_ttl = 255;
		dv4hdr->ip_hl = 5;
		dv4hdr->ip_v = 4;
		int ipsum;
		ipsum = cksum((uint16_t *)dv4hdr, dv4hdr->ip_hl * 4);

		while (ipsum >> 16)
			ipsum = (ipsum & 0xFFFF)+(ipsum >> 16);
		dv4hdr->ip_sum = ~ipsum;

		// localcopy of addr to make compiler happy
		uint16_t saddr[8];
		memcpy(saddr, &dv4hdr->ip_src, 8);
		tcpsum = cksum(saddr, 8);
		blen += sizeof(struct tcphdr);


	} 

	// Add the IPv6 header if any
	if (ipv6start != -1) {
		
		struct ip6_hdr *dv6hdr = (struct ip6_hdr *) (buffer + blen), *sv6hdr = (struct ip6_hdr *) (f->buff + ipv6start);
		memcpy(dv6hdr->ip6_src.s6_addr, sv6hdr->ip6_dst.s6_addr, sizeof(dv6hdr->ip6_src));
		memcpy(dv6hdr->ip6_dst.s6_addr, sv6hdr->ip6_src.s6_addr, sizeof(dv6hdr->ip6_dst));
		buffer[blen] = 0x6 << 4;
		dv6hdr->ip6_nxt = IPPROTO_TCP;
		dv6hdr->ip6_plen = htons(sizeof(struct tcphdr));
		dv6hdr->ip6_hlim = 255;

		tcpsum = cksum((uint16_t *)&dv6hdr->ip6_src, 32);
		blen += sizeof(struct ip6_hdr);

	} 

	// Add the tcp header
	struct tcphdr *dhdr = (struct tcphdr*) (buffer + blen);
	dhdr->th_sport = shdr->th_dport;
	dhdr->th_dport = shdr->th_sport;
	dhdr->th_seq = shdr->th_ack;
	dhdr->th_flags = TH_RST | TH_ACK;
	dhdr->th_ack = htonl(ntohl(shdr->th_seq) + 1);
	dhdr->th_win = shdr->th_win;
	dhdr->th_off = sizeof(struct tcphdr) / 4;

	blen += sizeof(struct tcphdr);

	tcpsum += ntohs(IPPROTO_TCP + sizeof(struct tcphdr));

	for (i = 0; i < priv->severity; i++) {

		dhdr->th_sum = 0;
		int mysum = tcpsum + cksum((uint16_t*)(dhdr), sizeof(struct tcphdr));
	
	    	while (mysum >> 16)
			mysum = (mysum & 0xFFFF)+(mysum >> 16);

		dhdr->th_sum = ~mysum;

		char errbuff[256];

		if (!priv->routed) {
			if (libnet_write_link (priv->lc, buffer, blen) == -1) {
				strerror_r(errno, errbuff, 256);
				dprint("Error while inject TCP ST : %s\n", errbuff);
				return 0;
			}
		}
#ifdef HAVE_LINUX_IP_SOCKET
		else {
			// Inject the packets
			if(sendto(priv->socket, (u_int8_t *)buffer, blen, 0, (struct sockaddr *) &addr, addrlen) <= 0) {
				strerror_r(errno, errbuff, 256);
				dprint("Error while inject TCP RST : %s\n", errbuff);
				return 0;
			}
		}
#endif
		dhdr->th_seq += htonl(ntohl(dhdr->th_seq) + ntohs(shdr->th_win));


	}

	dprint("0x%lx; TCP killed !\n", (unsigned long) priv);

	return 1;
	
}

int target_close_tcpkill(struct target *t) {

	if (!t->target_priv)
		return 0;

	struct target_priv_tcpkill *priv = t->target_priv;
	
	if (!priv->routed) {
		if (priv->lc)
			libnet_destroy(priv->lc);
	}
#ifdef HAVE_LINUX_IP_SOCKET
	else {
		close(priv->socket);
	}
#endif
	free(priv);
	t->target_priv = NULL;

	
	return 1;
}
