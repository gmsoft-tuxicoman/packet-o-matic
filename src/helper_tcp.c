/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007 Guy Martin <gmsoft@tuxicoman.be>
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

#include "helper_tcp.h"

#include <netinet/tcp.h>

/// We should receive the dropped data within the 10 seconds
#define TCP_PACKET_TIMEOUT 10


struct helper_priv_tcp *priv_head;

struct helper_functions *hlp_functions;
int helper_register_tcp(struct helper_reg *r, struct helper_functions *hlp_funcs) {
	
	r->need_help = helper_need_help_tcp;

	hlp_functions = hlp_funcs;

	return 1;
}

int helper_need_help_tcp(struct layer *l, void *frame, unsigned int start, unsigned int len) {


	struct tcphdr* hdr = frame + start;
	int payload_size;
	if (!l->prev)
		payload_size = len - (hdr->th_off << 2) - start;
	else
		payload_size = l->prev->payload_size - (hdr->th_off << 2);
	
	struct conntrack_entry *ce = (*hlp_functions->conntrack_get_entry) (l, frame);

	// We need to track all the tcp packets
	if (!ce) 
		ce = (*hlp_functions->conntrack_create_entry) (l, frame);
	
	uint32_t new_seq;
	new_seq = ntohl(hdr->th_seq);

	struct helper_priv_tcp *cp = (*hlp_functions->conntrack_get_priv) (l->type, ce);
	if (!cp) {
		// We don't know anything about this connection. let it go
		cp = malloc(sizeof(struct helper_priv_tcp));
		bzero(cp, sizeof(struct helper_priv_tcp));

		struct layer *first_layer = l;
		while (first_layer->prev)
			first_layer = first_layer->prev;

		cp->first_layer = first_layer->type;

		(*hlp_functions->conntrack_add_priv) (cp, l->type, ce, helper_flush_buffer_tcp, helper_cleanup_connection_tcp);
	}

	int dir = ce->direction != CT_DIR_REV ? 0 : 1;


	if (cp->flags[dir] & HELPER_TCP_SEQ_KNOWN) {
	
		if (new_seq < cp->seq_expected[dir]) {
			//dprint("helper_tcp.c: 0x%u, expected seq %u < got seq %u, dir is %u. discarding packet\n", (unsigned) ce, cp->seq_expected[dir], new_seq, dir);
			return 1;
		} else if (new_seq > cp->seq_expected[dir]) {
		
			// if there is no payload, there is no reason to queue the packet
			if (!payload_size)
				return 1;

			struct helper_priv_tcp_packet *pkt = malloc(sizeof(struct helper_priv_tcp_packet));
			bzero(pkt, sizeof(struct helper_priv_tcp_packet));
			
			pkt->len = len;
			pkt->buffer = malloc(len); // This will be fred by the helper subsystem itself
			if ((unsigned)pkt->buffer == 0x8b491f0)
				dprint("gotcha2\n");
			memcpy(pkt->buffer, frame, len);
			pkt->seq = new_seq;

			struct helper_priv_tcp_packet *tmp_pkt = cp->pkts[dir];

			if (!tmp_pkt) {
				cp->pkts[dir] = pkt;

			        (*hlp_functions->queue_timer) (cp->t[dir], TCP_PACKET_TIMEOUT);
			} else if (tmp_pkt->seq > new_seq) {
				pkt->next = tmp_pkt;
				cp->pkts[dir] = pkt;
			} else if (tmp_pkt->seq == new_seq){
				dprint("Discarding duplicate packet1\n");
				free(tmp_pkt->buffer);
				tmp_pkt->buffer = pkt->buffer;
				tmp_pkt->len = pkt->len;
				free(pkt);
				cp->seq_expected[dir] = pkt->seq + pkt->len;
				return 1;

			} else {
				while (tmp_pkt->next && tmp_pkt->next->seq < new_seq)
					tmp_pkt = tmp_pkt->next;
				if (tmp_pkt->next && tmp_pkt->next->seq == new_seq) {
					dprint("Discarding duplicate packet2\n");
					free(tmp_pkt->next->buffer);
					tmp_pkt->next->buffer = pkt->buffer;
					tmp_pkt->next->len = pkt->len;
					free(pkt);
					cp->seq_expected[dir] = pkt->seq + pkt->len;
					return 1;
				}
				pkt->next = tmp_pkt->next;
				tmp_pkt->next = pkt;

			}
			
			cp->buff_len[dir] += len;


			//dprint("helper_tcp.c: 0x%u, expected seq %u > seq %u, dir is %u. queuing packet 0x%x\n", (unsigned) ce, cp->seq_expected[dir], new_seq, dir, (unsigned)pkt->buffer);

			// Maybe we suffer from packet loss. We allow a max buffer of 256K
			if (cp->buff_len[dir] > 262144) {
				dprint("helper_tcp.c: warning, buffer is too large. we probably lost a packet. processing anyway. lost %u bytes cp = 0x%x, seq %u, expected %u\n", cp->seq_expected[dir] - cp->last_seq[dir], (unsigned) cp, cp->last_seq[dir], cp->seq_expected[dir]);
				helper_process_next_tcp(cp, dir);
			}
			return 1;
		}

		cp->last_seq[dir] = new_seq;

	} else {
		//dprint("Connection known now\n");
		cp->flags[dir] |= HELPER_TCP_SEQ_KNOWN;
		struct helper_timer_priv_tcp *tmp = malloc(sizeof(struct helper_timer_priv_tcp));
		bzero(tmp, sizeof(struct helper_timer_priv_tcp));
		tmp->priv = cp;
		tmp->dir = dir;
		cp->t[dir] = (*hlp_functions->alloc_timer) (tmp, helper_process_timer_tcp);
	}
	
	cp->seq_expected[dir] = new_seq + payload_size;

	if (hdr->th_flags & TH_SYN || hdr->th_flags & TH_FIN)
		cp->seq_expected[dir]++;

	// Let's see if we can dequeue the next packets now
	if (cp->pkts[dir] && cp->pkts[dir]->seq == cp->seq_expected[dir]) 
		helper_process_next_tcp(cp, dir);

	return 0;
}

int helper_process_timer_tcp(void *priv) {

	struct helper_timer_priv_tcp *p = priv;
	dprint("helper_tcp.c: warning, timer expired for missing segment. processing anyway. lost %u bytes cp = 0x%x, seq %u, expected %u\n", p->priv->seq_expected[p->dir] - p->priv->last_seq[p->dir], (unsigned) p->priv, p->priv->last_seq[p->dir], p->priv->seq_expected[p->dir]);
	return helper_process_next_tcp(p->priv, p->dir);

}

int helper_process_next_tcp(struct helper_priv_tcp *p, int dir) {


	struct helper_priv_tcp_packet *pkt = p->pkts[dir];
	p->pkts[dir] = p->pkts[dir]->next;

	p->buff_len[dir] -= pkt->len;
	p->seq_expected[dir] = pkt->seq;
	(*hlp_functions->queue_frame) (pkt->buffer, pkt->len, p->first_layer);

	free(pkt);

	if (p->t[dir]) {

		(*hlp_functions->dequeue_timer) (p->t[dir]);

		if (p->pkts[dir])
			(*hlp_functions->queue_timer) (p->t[dir], TCP_PACKET_TIMEOUT);
	}

	return 1;
}


int helper_flush_buffer_tcp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_tcp *cp = conntrack_priv;

	if (cp->pkts[0]) {
		helper_process_next_tcp(cp, 0);
		return 1;
	}

	if (cp->pkts[1]) {
		helper_process_next_tcp(cp, 1);
		return 1;
	}

	return 0;
}

int helper_cleanup_connection_tcp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_tcp *cp = conntrack_priv;

#ifdef DEBUG
	if (cp->pkts[0] || cp->pkts[1]) {
		dprint("helper_tcp : There should not be any remaining packet at this point !!!!\n");
	}
#endif

	if (cp->t[0]) {
		(*hlp_functions->dequeue_timer) (cp->t[0]);
		free (cp->t[0]->priv);
		(*hlp_functions->cleanup_timer) (cp->t[0]);
		cp->t[0] = NULL;
	}

	if (cp->t[1]) {
		(*hlp_functions->dequeue_timer) (cp->t[1]);
		free (cp->t[1]->priv);
		(*hlp_functions->cleanup_timer) (cp->t[1]);
		cp->t[1] = NULL;
	}

		
	free(cp);
	return 1;
}

