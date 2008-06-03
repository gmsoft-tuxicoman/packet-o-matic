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

#include "target_tcpkill.h"
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include "ptype_uint16.h"
#include "ptype_string.h"

#ifdef HAVE_LINUX_IP_SOCKET
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#endif

#include <netinet/tcp.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

static int cksum(uint16_t *addr, int len)
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


static int match_ipv4_id, match_ipv6_id, match_tcp_id, match_ethernet_id;

static struct target_mode *mode_routed, *mode_interface;

int target_register_tcpkill(struct target_reg *r) {

	r->init = target_init_tcpkill;
	r->open = target_open_tcpkill;
	r->process = target_process_tcpkill;
	r->close = target_close_tcpkill;
	r->cleanup = target_cleanup_tcpkill;

	match_ipv4_id = match_register("ipv4");
	match_ipv6_id = match_register("ipv6");
	match_tcp_id = match_register("tcp");
	match_ethernet_id = match_register("ethernet");


	mode_interface = target_register_mode(r->type, "interface", "Send packet to specified interface");
	if (!mode_interface)
		return POM_ERR;

	target_register_param(mode_interface, "severity", "2", "Number of TCP RST packet to send for each received packet");
	target_register_param(mode_interface, "interface", "eth0", "Interface where to send TCP RST");

#ifdef HAVE_LINUX_IP_SOCKET

	mode_routed = target_register_mode(r->type, "routed", "Send packets using routing table (ipv4 only)");
	if (!mode_routed)
		return POM_ERR;
	target_register_param(mode_routed, "severity", "2", "Number of TCP RST packet to send for each received packet");
#endif 


	return POM_OK;

}


static int target_init_tcpkill(struct target *t) {

	if (match_tcp_id == -1)
		return POM_ERR;

	struct target_priv_tcpkill *priv = malloc(sizeof(struct target_priv_tcpkill));
	memset(priv, 0, sizeof(struct target_priv_tcpkill));

	t->target_priv = priv;
	
	priv->severity = ptype_alloc("uint16", NULL);
	priv->interface = ptype_alloc("string", NULL);
	
	if (!priv->severity || !priv->interface) {
		target_cleanup_tcpkill(t);
		return POM_ERR;
	}

#ifdef HAVE_LINUX_IP_SOCKET
	target_register_param_value(t, mode_routed, "severity", priv->severity);
#endif

	target_register_param_value(t, mode_interface, "interface", priv->interface);
	target_register_param_value(t, mode_interface, "severity", priv->severity);


	return POM_OK;
}

static int target_cleanup_tcpkill(struct target *t) {

	struct target_priv_tcpkill *priv = t->target_priv;

	if (priv) {
		ptype_cleanup(priv->interface);
		ptype_cleanup(priv->severity);
		free(priv);
	}

	return POM_OK;
}

static int target_open_tcpkill(struct target *t) {

	struct target_priv_tcpkill *p = t->target_priv;
	
	if (!p) {
		pom_log(POM_LOG_ERR "Error, tcpkill target not initialized !\r\n");
		return POM_ERR;
	}


#ifdef HAVE_LINUX_IP_SOCKET
	if (t->mode == mode_routed) {

		int one = 1;

		// Open IPv4 socket

		p->socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

		if (p->socket < 0) {
			pom_log(POM_LOG_ERR "Unable to open IPv4 socket to send TCP RST\r\n");
			return POM_ERR;
		}
		if (setsockopt (p->socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0) {
			pom_log(POM_LOG_ERR "Unable to set IP_HDRINCL on IPv4 socket !\r\n");
			return POM_ERR;
		}
	} else {
#endif

		char errbuf[LIBNET_ERRBUF_SIZE];

		p->lc = libnet_init (LIBNET_LINK_ADV, PTYPE_STRING_GETVAL(p->interface), errbuf);
	        if (!p->lc) {
			pom_log(POM_LOG_ERR "Error, cannot open libnet context: %s\r\n", errbuf);
			return POM_ERR;
		}
      		pom_log(POM_LOG_ERR "Libnet context initialized for interface %s\r\n", p->lc->device);
#ifdef HAVE_LINUX_IP_SOCKET
	}
#endif

	return POM_OK;
}

static int target_process_tcpkill(struct target *t, struct frame *f) {


	struct target_priv_tcpkill *priv = t->target_priv;


	int ipv4start, ipv6start, tcpstart, i;

	tcpstart = layer_find_start(f->l, match_tcp_id);
	if (tcpstart == POM_ERR) {
		pom_log(POM_LOG_WARN "No TCP header found in this packet\r\n");
		return POM_OK;
	}

	struct tcphdr *shdr = (struct tcphdr*) (f->buff + tcpstart);

	// No need to kill RST or FIN packets
	if ((shdr->th_flags & TH_RST) || (shdr->th_flags & TH_FIN))
		return POM_OK;

	ipv4start = layer_find_start(f->l, match_ipv4_id);
	ipv6start = layer_find_start(f->l, match_ipv6_id);

	// init temp buffer
	unsigned char buffer_base[1024];
	memset(buffer_base, 0, 1024);
	unsigned char *buffer = (unsigned char*) (((long)buffer_base & ~3) + 4);

	int tcpsum = 0;
	int blen = 0; // Buffer len

#ifdef HAVE_LINUX_IP_SOCKET
	// init sockaddr
	struct sockaddr_storage addr;
	socklen_t addrlen = 0;
	memset(&addr, 0, sizeof(struct sockaddr_storage));


	// In routed mode, we can only send ipv4 packets. linux API doesn't allow random souce addr for ipv6
	if (t->mode == mode_routed && ipv4start == -1) {
		pom_log(POM_LOG_WARN "No IPv4 header found in this packet\r\n");
		return POM_OK;
	}
#endif

	// In normal mode we need at least an ipv6 or ipv4 header
	if (t->mode != mode_routed && ipv4start == -1 && ipv6start == -1) {
		pom_log(POM_LOG_WARN "No IPv4 or IPv6 header found in this packet\r\n");
		return POM_OK;
	}

#ifdef HAVE_LINUX_IP_SOCKET
	// Check if the socket is opened
	if (t->mode == mode_routed && priv->socket <= 0) {
		pom_log(POM_LOG_ERR "Error, socket not opened. Cannot send TCP RST\r\n");
		return POM_ERR;
	}
#endif

	// In normal mode, we have to include the ethernet header
	if (t->mode != mode_routed) {
		int ethernetstart;
		ethernetstart = layer_find_start(f->l, match_ethernet_id);
		if (ethernetstart == POM_ERR) {
			pom_log(POM_LOG_WARN "No ethernet header found in this packet\r\n");
			return POM_OK;
		}

		// align the buffer on a 4+2 bytes boundary;
		buffer += 2;
		
		ipv6start = layer_find_start(f->l, match_ipv6_id);

		if (ipv4start == POM_ERR && ipv6start == POM_ERR) {
			pom_log(POM_LOG_WARN "Neither IPv4 or IPv6 header found in this packet\r\n");
			return POM_OK;
		}

		// First copy create the right ethernet header
		
		struct ether_header *dehdr = (struct ether_header*) buffer, *sehdr = (struct ether_header*) (f->buff + ethernetstart);
		memcpy(dehdr->ether_shost, sehdr->ether_dhost, sizeof(dehdr->ether_shost));
		memcpy(dehdr->ether_dhost, sehdr->ether_shost, sizeof(dehdr->ether_dhost));
		dehdr->ether_type = sehdr->ether_type;

		blen = sizeof(struct ether_header);

	}

	// Let's see if we have a IPv4 header. This can only be false in normal mode in case of an IPv6 packet
	if (ipv4start != POM_ERR) {

		struct ip *dv4hdr = (struct ip*) (buffer + blen), *sv4hdr = (struct ip*) (f->buff + ipv4start);
	
#ifdef HAVE_LINUX_IP_SOCKET
		if (t->mode == mode_routed) { // Create the right sockaddr_in in routed mode
			struct sockaddr_in *sin = (struct sockaddr_in *) &addr;
			addrlen = sizeof(struct sockaddr_in);
			sin->sin_family = AF_INET;
			memcpy(&sin->sin_addr, &sv4hdr->ip_src, sizeof(struct in_addr));
			sin->sin_port = shdr->th_sport;
		}
#endif

		dv4hdr->ip_src = sv4hdr->ip_dst;
		dv4hdr->ip_dst = sv4hdr->ip_src;
		if (ipv6start != POM_ERR) { // IPv6 in IPv4
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
	if (ipv6start != POM_ERR) {
		
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

	for (i = 0; i < PTYPE_UINT16_GETVAL(priv->severity); i++) {

		dhdr->th_sum = 0;
		int mysum = tcpsum + cksum((uint16_t*)(dhdr), sizeof(struct tcphdr));
	
	    	while (mysum >> 16)
			mysum = (mysum & 0xFFFF)+(mysum >> 16);

		dhdr->th_sum = ~mysum;

		char errbuff[256];

		if (t->mode != mode_routed) {
			if (libnet_write_link (priv->lc, buffer, blen) == -1) {
				strerror_r(errno, errbuff, 256);
				pom_log(POM_LOG_ERR "Error while inject TCP RST : %s\r\n", errbuff);
				return POM_ERR;
			}
		}
#ifdef HAVE_LINUX_IP_SOCKET
		else {
			// Inject the packets
			if(sendto(priv->socket, (u_int8_t *)buffer, blen, 0, (struct sockaddr *) &addr, addrlen) <= 0) {
				strerror_r(errno, errbuff, 256);
				pom_log(POM_LOG_ERR "Error while inject TCP RST : %s\r\n", errbuff);
				return POM_ERR;
			}
		}
#endif
		dhdr->th_seq += htonl(ntohl(dhdr->th_seq) + ntohs(shdr->th_win));


	}

	pom_log(POM_LOG_DEBUG "0x%lx; TCP killed !\r\n", (unsigned long) priv);

	return POM_OK;
	
}

static int target_close_tcpkill(struct target *t) {

	if (!t->target_priv)
		return POM_ERR;

	struct target_priv_tcpkill *priv = t->target_priv;
	
	if (t->mode != mode_routed) {
		if (priv->lc)
			libnet_destroy(priv->lc);
	}
#ifdef HAVE_LINUX_IP_SOCKET
	else {
		close(priv->socket);
	}
#endif
	
	return POM_OK;
}
