
#include <errno.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "target_tcpkill.h"

#define PARAMS_NUM 1

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
};

int match_ipv4_id, match_ipv6_id, match_tcp_id;

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
	if (match_tcp_id == -1)
		return 0;

	struct target_priv_tcpkill *priv = malloc(sizeof(struct target_priv_tcpkill));
	bzero(priv, sizeof(struct target_priv_tcpkill));

	priv->socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

	if (priv->socket < 0) {
		dprint("Unable to open socket to send TCP RST\n");
		free(priv);
		return 0;
	}
	
	int one = 1;
	if (setsockopt (priv->socket, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0) {
		dprint("Unable to set IP_HDRINCL on socket !\n");
		return 0;
	}


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

	return 1;
}

int target_process_tcpkill(struct target *t, struct rule_node *node, void *frame, unsigned int len) {
	
	struct target_priv_tcpkill *priv = t->target_priv;

	if (priv->socket <= 0) {
		dprint("Error, tcpkill target not opened !\n");
		return 0;
	}
	int ipv4start, ipv6start, tcpstart;
	ipv4start = node_find_header_start(node, match_ipv4_id);
	ipv6start = node_find_header_start(node, match_ipv6_id);
	tcpstart = node_find_header_start(node, match_tcp_id);

	if (ipv4start == -1 && ipv6start == -1) {
		dprint("Unable to find either ipv4 or ipv6 header\n");
		return 0;
	}
	if (tcpstart == -1) {
		dprint("No TCP header found in this packet\n");
		return 0;
	}

	struct sockaddr_in sin;
	bzero(&sin, sizeof(struct sockaddr_in));

	char buffer[1024]; // FIXME sizeof(struct iphdr) + sizeof(struct tcphdr);
	bzero(buffer, 1024);
	int pos, blen;

	int sum = 0;

	if (ipv4start != -1 ) {
	
		blen = sizeof(struct iphdr) + sizeof(struct tcphdr);
		pos = sizeof(struct iphdr);
		struct iphdr *dv4hdr = (struct iphdr*) buffer, *sv4hdr = (struct iphdr *) (frame + ipv4start);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = sv4hdr->saddr;
		dv4hdr->saddr = sv4hdr->daddr;
		dv4hdr->daddr = sv4hdr->saddr;
		dv4hdr->protocol = sv4hdr->protocol;
		dv4hdr->ttl = 255;
		dv4hdr->ihl = 5;
		dv4hdr->version = 4;
		dv4hdr->tot_len = blen;

		sum = cksum((__u16 *)&dv4hdr->saddr, 8);


	} else if (ipv6start != -1) {
/*		blen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
		buffer = malloc(blen);
		bzero(buffer, blen);
		struct ipv6_hdr *dv6hdr = buffer, sv6hdr = frame + ipv6start;
		memcpy(dv6hdr->saddr, sv6hdr->daddr, sizeof(dv6hdr->saddr));
		memcpy(dv6hdr->daddr, sv6hdr->saddr, sizeof(dv6hdr->daddr));*/

		dprint("IPv6 packets are not yet supported for target tcpkill\n");

		return 0;
	} else {
		// Error
		dprint("Error, shouldn't be reached !\n");
		return 0;
	}

	struct tcphdr *dhdr = (struct tcphdr*) (buffer + pos), *shdr = (struct tcphdr*) (frame + tcpstart);
	sin.sin_port = shdr->source;
	dhdr->source = shdr->dest;
	dhdr->dest = shdr->source;
	dhdr->seq = shdr->ack_seq;
	dhdr->rst = 1;
	dhdr->ack_seq = shdr->seq;
	dhdr->window = shdr->window;
	dhdr->doff = sizeof(struct tcphdr) / 4;


	sum += ntohs(IPPROTO_TCP + sizeof(struct tcphdr));

	int i;
	for (i = 0; i < priv->severity; i++) {
		dhdr->check = 0;
		dhdr->seq += shdr->window;


		int mysum = sum + cksum((__u16*)(dhdr), sizeof(struct tcphdr));
	
	    	while (mysum >> 16)
			mysum = (mysum & 0xFFFF)+(mysum >> 16);

		dhdr->check = ~mysum;

		if(sendto(priv->socket, buffer, blen, 0, (struct sockaddr *) &sin, sizeof(sin)) == -1) {
			dprint("Error while inject TCP RST : %s\n", strerror(errno));
			return 0;
		}

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
