
#include <errno.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>

#include "target_tcpkill.h"

#define PARAMS_NUM 3

int cksum(__u16 *addr, int len)
{
    int sum;
    __u16 last_byte;

    sum = 0;
    last_byte = 0;

    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1)
    {
        *(u_int8_t*)&last_byte = *(u_int8_t*)addr;
        sum += last_byte;
    }

    return (sum);
}


char *target_tcpkill_params[PARAMS_NUM][3] = {
	{ "severity", "2", "numbers of tcp rst packet by try"},
	{ "mode", "routed", "operating mode : 'routed' (default) let linux decide where to send packets to but is IPv4 only. 'normal' send the packet to the specified interface"},
	{ "interface", "eth0", "interface to send packets to in non routed mode" },
};

int match_ipv4_id, match_ipv6_id, match_tcp_id, match_ethernet_id;

int target_register_tcpkill(struct target_reg *r) {

	copy_params(r->params_name, target_tcpkill_params, 0, PARAMS_NUM);
	copy_params(r->params_help, target_tcpkill_params, 2, PARAMS_NUM);


	r->init = target_init_tcpkill;
	r->open = target_open_tcpkill;
	r->process = target_process_tcpkill;
	r->close = target_close_tcpkill;
	r->cleanup = target_cleanup_tcpkill;


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


	match_ipv4_id = (*t->match_register) ("ipv4");
	match_ipv6_id = (*t->match_register) ("ipv6");
	match_tcp_id = (*t->match_register) ("tcp");
	match_ethernet_id = (*t->match_register) ("ethernet");
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
		dprint("Wront severity parameter to target_tcpkill !\n");
		p->severity = 2;
	}

	if (!strcmp(t->params_value[1], "routed")) {
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

		p->socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

		if (p->socket < 0) {
			dprint("Unable to open ethernet socket to send TCP RST\n");
			return 0;
		}

		// find out the interface number
		struct ifreq req;
		strcpy(req.ifr_name, t->params_value[2]);
		if (ioctl(p->socket, SIOCGIFINDEX, &req)) {
			dprint("Interface %s not found\n", t->params_value[2]);
			return 0;
		}
		dprint("Found interface number %u\n", req.ifr_ifindex);

		p->ifindex = req.ifr_ifindex;

	}


	return 1;
}

int target_process_tcpkill(struct target *t, struct rule_node *node, void *frame, unsigned int len) {


	struct target_priv_tcpkill *priv = t->target_priv;


	int ipv4start, tcpstart;

	tcpstart = node_find_header_start(node, match_tcp_id);
	if (tcpstart == -1) {
		dprint("No TCP header found in this packet\n");
		return 0;
	}

	struct tcphdr *shdr = (struct tcphdr*) (frame + tcpstart);

	ipv4start = node_find_header_start(node, match_ipv4_id);

	struct sockaddr_storage addr;
	socklen_t addrlen;
	bzero(&addr, sizeof(struct sockaddr_storage));

	char buffer[1024];
	bzero(buffer, 1024);

	int tcpsum;
	int blen = 0; // Buffer len

	if (priv->routed) {
		
		if (ipv4start == -1) {
			dprint("No IPv4 header found in this packet\n");
			return 0;
		}

		if (priv->socket <= 0) {
			dprint("Error, IPv4 socket not opened. Cannot send TCP RST\n");
			return 0;
		}

		blen = sizeof(struct iphdr);
		struct iphdr *dv4hdr = (struct iphdr*) buffer, *sv4hdr = (struct iphdr *) (frame + ipv4start);
		struct sockaddr_in *sin = (struct sockaddr_in *) &addr;
		addrlen = sizeof(struct sockaddr_in);
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = sv4hdr->saddr;
		sin->sin_port = shdr->source;
		dv4hdr->saddr = sv4hdr->daddr;
		dv4hdr->daddr = sv4hdr->saddr;
		dv4hdr->protocol = IPPROTO_TCP;
		dv4hdr->ttl = 255;
		dv4hdr->ihl = 5;
		dv4hdr->version = 4;
		dv4hdr->tot_len = blen;

		tcpsum = cksum((__u16 *)&dv4hdr->saddr, 8);


	} else {

		int ipv6start, ethernetstart;
		ethernetstart = node_find_header_start(node, match_ethernet_id);
		if (ethernetstart == -1) {
			dprint("No ethernet header found in this packet\n");
			return 0;
		}
		
		ipv6start = node_find_header_start(node, match_ipv6_id);

		if (ipv4start == -1 && ipv6start == -1) {
			dprint("Neither IPv4 or IPv6 header found in this packet\n");
			return 0;
		}

		// First copy create the right ethernet header
		
		struct ethhdr *dehdr = (struct ethhdr *) buffer, *sehdr = (struct ethhdr*) (frame + ethernetstart);
		memcpy(dehdr->h_source, sehdr->h_dest, sizeof(dehdr->h_source));
		memcpy(dehdr->h_dest, sehdr->h_source, sizeof(dehdr->h_dest));
		dehdr->h_proto = sehdr->h_proto;

		struct sockaddr_ll *sal = (struct sockaddr_ll *) &addr;
		addrlen = sizeof(struct sockaddr_ll);
		sal->sll_family = AF_PACKET;
		sal->sll_halen = 6;
		sal->sll_ifindex = priv->ifindex;

		blen = sizeof(struct ethhdr);


		if (ipv4start != -1) {

			struct iphdr *dv4hdr = (struct iphdr*) (buffer + blen), *sv4hdr = (struct iphdr *) (frame + ipv4start);
			dv4hdr->saddr = sv4hdr->daddr;
			dv4hdr->daddr = sv4hdr->saddr;
			dv4hdr->protocol = IPPROTO_TCP;
			dv4hdr->ttl = 255;
			dv4hdr->ihl = 5;
			dv4hdr->version = 4;
			dv4hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
			int ipsum;
			ipsum = cksum((__u16 *)dv4hdr, dv4hdr->ihl * 4);

	    		while (ipsum >> 16)
				ipsum = (ipsum & 0xFFFF)+(ipsum >> 16);
			dv4hdr->check = ~ipsum;

			tcpsum = cksum((__u16 *)&dv4hdr->saddr, 8);
			blen += sizeof(struct tcphdr);


		} else if (ipv6start != -1) {
			
			struct ip6_hdr *dv6hdr = (struct ip6_hdr *) (buffer + blen), *sv6hdr = (struct ip6_hdr *) (frame + ipv6start);
			memcpy(dv6hdr->ip6_src.s6_addr, sv6hdr->ip6_dst.s6_addr, sizeof(dv6hdr->ip6_src));
			memcpy(dv6hdr->ip6_dst.s6_addr, sv6hdr->ip6_src.s6_addr, sizeof(dv6hdr->ip6_dst));
			buffer[blen] = 0x6 << 4;
			dv6hdr->ip6_nxt = IPPROTO_TCP;
			dv6hdr->ip6_plen = htons(sizeof(struct tcphdr));
			dv6hdr->ip6_hlim = 255;

			tcpsum = cksum((__u16 *)&dv6hdr->ip6_src, 32);
			blen += sizeof(struct ip6_hdr);

		} else {
			dprint("ERROR : Shouldn't be reached\n");
			return 0;
		}

	}




		
	struct tcphdr *dhdr = (struct tcphdr*) (buffer + blen);
	dhdr->source = shdr->dest;
	dhdr->dest = shdr->source;
	dhdr->seq = shdr->ack_seq;
	dhdr->rst = 1;
	dhdr->ack_seq = shdr->seq;
	dhdr->window = shdr->window;
	dhdr->doff = sizeof(struct tcphdr) / 4;

	blen += sizeof(struct tcphdr);

	tcpsum += ntohs(IPPROTO_TCP + sizeof(struct tcphdr));

	int i;
	for (i = 0; i < priv->severity; i++) {

		int mysum = tcpsum + cksum((__u16*)(dhdr), sizeof(struct tcphdr));
	
	    	while (mysum >> 16)
			mysum = (mysum & 0xFFFF)+(mysum >> 16);

		dhdr->check = ~mysum;

		if(sendto(priv->socket, buffer, blen, 0, (struct sockaddr *) &addr, addrlen) <= 0) {
			dprint("Error while inject TCP RST : %s\n", strerror(errno));
			return 0;
		}


		dhdr->seq += shdr->window;

	}

	dprint("0x%x; TCP killed !\n", (unsigned) priv);

	return 1;
	
}

int target_close_tcpkill(struct target *t) {

	if (!t->target_priv)
		return 0;

	struct target_priv_tcpkill *priv = t->target_priv;

	close(priv->socket);
	free(priv);
	t->target_priv = NULL;

	
	return 1;
}