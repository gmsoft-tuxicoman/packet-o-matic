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

//#define NDEBUG 1

#include "helper_tcp.h"

#include "ptype_uint32.h"

#include <netinet/tcp.h>

struct ptype *pkt_timeout;
struct ptype *conn_buff;

// Helps to track all the connections
struct helper_priv_tcp *conn_head;

struct helper_functions *hlp_functions;
int helper_register_tcp(struct helper_reg *r, struct helper_functions *hlp_funcs) {
	
	r->need_help = helper_need_help_tcp;
	r->cleanup = helper_cleanup_tcp;

	hlp_functions = hlp_funcs;

	pkt_timeout = (*hlp_funcs->ptype_alloc) ("uint32", "Number of seconds to wait for out of order packets", "seconds");
	if (!pkt_timeout)
		return H_ERR;
	
	conn_buff = (*hlp_funcs->ptype_alloc) ("uint32", "Maximum KBytes of buffer per connection", "KBytes");
	if (!conn_buff) {
		(*hlp_funcs->ptype_cleanup) (pkt_timeout);
		return H_ERR;
	}

	conn_head = NULL;

	(*hlp_funcs->register_param) (r->type, "pkt_timeout", "30", pkt_timeout);
	(*hlp_funcs->register_param) (r->type, "conn_buffer", "256", conn_buff);


	return H_OK;
}

int helper_need_help_tcp(struct frame *f, unsigned int start, unsigned int len, struct layer *l) {


	struct tcphdr* hdr = f->buff + start;
	int payload_size = l->payload_size;

	if (!payload_size) // We don't need to reorder empty packets
		return H_OK;

	// We need to track all the tcp packets
	if (!f->ce)
		if ((*hlp_functions->conntrack_get_entry) (f) == C_ERR)
			(*hlp_functions->conntrack_create_entry) (f);
	
	uint32_t new_seq, new_ack;
	new_seq = ntohl(hdr->th_seq);
	new_ack = ntohl(hdr->th_ack);

	struct helper_priv_tcp *cp = (*hlp_functions->conntrack_get_priv) (l->type, f->ce);
	if (!cp) {
		// We don't know anything about this connection. let it go
		cp = malloc(sizeof(struct helper_priv_tcp));
		bzero(cp, sizeof(struct helper_priv_tcp));

		cp->ce = f->ce;

		if (!conn_head)
			conn_head = cp;
		else {
			cp->next = conn_head;
			cp->next->prev = cp;
			conn_head = cp;
		}

		(*hlp_functions->conntrack_add_priv) (cp, l->type, f->ce, helper_flush_buffer_tcp, helper_cleanup_connection_tcp);
	}

	int dir = f->ce->direction != CT_DIR_REV ? 0 : 1;

	if (cp->flags[dir] & HELPER_TCP_SEQ_KNOWN) {
	
		if (new_seq + payload_size < cp->seq_expected[dir]) {
			ndprint("helper_tcp.c: %u.%u 0x%x-%u, expected seq %u < got seq %u, bufflen is %d. discarding packet\n", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, cp->seq_expected[dir], new_seq, cp->buff_len[dir]);
			return 1;
		} else if (new_seq > cp->seq_expected[dir]) {
		

			struct helper_priv_tcp_packet *tmp_pkt = cp->pkts[dir];

			if (tmp_pkt) {
				// There is something in the queue
				// Let's see where to put our packet
				

				// Go up to seq of packet in the queue is >= to the current one
				while (tmp_pkt && tmp_pkt->seq < new_seq) 
					tmp_pkt = tmp_pkt->next;

				if (tmp_pkt && tmp_pkt->seq == new_seq) {

					// We got a packet with an existing seq in the queue
					// There are a few possibilities
					//  - it's a retransmit of an old packet -> payload size of both packet != 0 and is the same -> we discard it
					//  - it's a retransmit with a different size -> payload size of both packet != 0 and payload size differ -> we keep the biggest one
					//  - it's a ACK with 0 payload -> we keep it

					while (tmp_pkt && tmp_pkt->seq == new_seq) {
						
						if (payload_size == 0) {
							// we are dealing with a ack here
							// we don't really care where it'll end up in the queue so let's queue it at the end
							if (tmp_pkt->ack == new_ack) {
								// got duplicate. discard it
								return H_NEED_HELP;
							}

						} else {
							// we are dealing with a packed with some payload
							if (tmp_pkt->data_len == 0) { // we don't care about ACKs
								tmp_pkt = tmp_pkt->next;
								continue;
							} else {
								// looks like we already got a packet with some payload
								if (tmp_pkt->data_len >= payload_size) {
									// same payload size -> we can safely discard it
									ndprint("helper_tcp.c: %u.%u 0x%x-%u, got seq %u, bufflen is %d. discarding duplicate already in the queue\n", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, new_seq, cp->buff_len[dir]);
									return H_NEED_HELP;
								} else {
									ndprint("helper_tcp.c: %u.%u 0x%x-%u, got seq %u, bufflen is %d. replacing duplicate already in the queue\n", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, new_seq, cp->buff_len[dir]);
									cp->buff_len[dir] += payload_size - tmp_pkt->data_len;

									free(tmp_pkt->f->buff);
									free(tmp_pkt->f);
									tmp_pkt->f = malloc(sizeof(struct frame));
									memcpy(tmp_pkt->f, f, sizeof(struct frame));
									tmp_pkt->f->buff = malloc(f->len);
									memcpy(tmp_pkt->f->buff, f->buff, f->len);
									tmp_pkt->f->bufflen = f->len;
									tmp_pkt->seq = new_seq;
									tmp_pkt->ack = new_ack;
									tmp_pkt->data_len = payload_size;
									return H_NEED_HELP;
								}
							}
						}

						tmp_pkt = tmp_pkt->next;
					}
				}
				
			}

			// At this point we need to queue the packet before tmp_pkt or at the end of the list if empty
			ndprint("helper_tcp.c: %u.%u 0x%x-%u, expected seq %u > got seq %u, bufflen is %d. queuing packet\n", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, cp->seq_expected[dir], new_seq, cp->buff_len[dir]);

			struct helper_priv_tcp_packet *pkt = malloc(sizeof(struct helper_priv_tcp_packet));
			bzero(pkt, sizeof(struct helper_priv_tcp_packet));

			// This will be fred by the helper subsystem
			pkt->f = malloc(sizeof(struct frame));
			memcpy(pkt->f, f, sizeof(struct frame));
			pkt->f->buff = malloc(f->len);
			memcpy(pkt->f->buff, f->buff, f->len);
			pkt->f->bufflen = f->len;
			
			pkt->seq = new_seq;
			pkt->ack = new_ack;
			pkt->data_len = payload_size;

			if (tmp_pkt) {

				pkt->next = tmp_pkt;
				pkt->prev = tmp_pkt->prev;
				tmp_pkt->prev = pkt;

				if (pkt->prev)
					pkt->prev->next = pkt;
				else
					cp->pkts[dir] = pkt;
			} else {
				// We reached the end of the list
				pkt->prev = cp->pkts_tail[dir];
				cp->pkts_tail[dir] = pkt;
				if (pkt->prev) {
					pkt->prev->next = pkt;
				} else {
					// This is the first packet in the queue
					cp->pkts[dir] = pkt;
					(*hlp_functions->queue_timer) (cp->t[dir], PTYPE_UINT32_GETVAL(pkt_timeout));
				}

			}


			
			cp->buff_len[dir] += f->len;


			// Maybe we suffer from packet loss. Default maximum buffer is 256 KBytes 
			if (cp->buff_len[dir] > PTYPE_UINT32_GETVAL(conn_buff) * 1024) {
				ndprint("helper_tcp.c: 0x%x-%u, warning, buffer is too large : %u. we probably lost a packet. processing anyway. lost %u bytes cp = 0x%x, seq %u, expected %u\n", (unsigned) f->ce, dir, cp->buff_len[dir], cp->seq_expected[dir] - cp->last_seq[dir], (unsigned) cp, cp->last_seq[dir], cp->seq_expected[dir]);
				helper_process_next_tcp(cp, dir);
			}

			return H_NEED_HELP;
		}


	} else {
		//dprint("Connection known now\n");
		cp->flags[dir] |= HELPER_TCP_SEQ_KNOWN;
		struct helper_timer_priv_tcp *tmp = malloc(sizeof(struct helper_timer_priv_tcp));
		bzero(tmp, sizeof(struct helper_timer_priv_tcp));
		tmp->priv = cp;
		tmp->dir = dir;
		cp->t[dir] = (*hlp_functions->alloc_timer) (tmp, f->input, helper_process_timer_tcp);
	}

	cp->last_seq[dir] = new_seq;
	
	cp->seq_expected[dir] = new_seq + payload_size;
	if (hdr->th_flags & TH_SYN || hdr->th_flags & TH_FIN)
		cp->seq_expected[dir]++;

	ndprint("helper_tcp.c: %u.%u 0x%x-%u, got seq %u, new expected seq %u, bufflen is %d. processing packet\n", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, new_seq, cp->seq_expected[dir], cp->buff_len[dir]);

	// Discard any packet that we are sure not to need anymore
	while (cp->pkts[dir] && ((cp->pkts[dir]->seq + cp->pkts[dir]->data_len) < cp->seq_expected[dir])) {
		ndprint("helper_tcp.c: 0x%x-%u, discarding packet with seq %u from queue\n", (unsigned) f->ce, dir, cp->pkts[dir]->seq);
		struct helper_priv_tcp_packet *pkt = cp->pkts[dir];
		cp->pkts[dir] = cp->pkts[dir]->next;
		if (cp->pkts[dir]) {
			cp->pkts[dir]->prev = NULL;
		} else {
			(*hlp_functions->dequeue_timer) (cp->t[dir]);
			cp->pkts_tail[dir] = NULL;
		}
		cp->buff_len[dir] -= pkt->f->len;
		free(pkt->f->buff);
		free(pkt->f);
		free(pkt);

	}

	// Let's see if we can dequeue the next packets now
	if (cp->pkts[dir]) {
		ndprint("helper_tcp.c: %u.%u 0x%x-%u, expected seq %u, first packet in queue seq %u\n", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, cp->seq_expected[dir], cp->pkts[dir]->seq);
		if (cp->pkts[dir]->seq == cp->seq_expected[dir]) {
			// It's easy, the sequence number match !
			helper_process_next_tcp(cp, dir);
		} else if (cp->pkts[dir]->seq < cp->seq_expected[dir] && // packet must be before what we expect
				cp->pkts[dir]->seq + cp->pkts[dir]->data_len >= cp->seq_expected[dir] && 
				(!cp->pkts[dir]->next || cp->pkts[dir]->seq + cp->pkts[dir]->data_len < cp->pkts[dir]->next->seq + cp->pkts[dir]->next->data_len)) {
			// Looks like we need already have data from this packet in the buffer
			unsigned int dup_data_len = cp->seq_expected[dir] - cp->pkts[dir]->seq;
			ndprint("helper_tcp.c: 0x%x-%u, need to drop %u of data over %u from current packet\n", (unsigned) f->ce, dir, dup_data_len, payload_size);
			l->payload_size -= dup_data_len;
			helper_process_next_tcp(cp, dir);
		}
		
	}
/*
	if (cp->t[dir] && cp->pkts[dir]) {
		(*hlp_functions->dequeue_timer) (cp->t[dir]);
		(*hlp_functions->queue_timer) (cp->t[dir], PTYPE_UINT32_GETVAL(pkt_timeout));
	}
*/
	return H_OK;
}

int helper_process_timer_tcp(void *priv) {

	struct helper_timer_priv_tcp *p = priv;
	if (!p->priv->pkts[p->dir]) {
		dprint("helper_tcp.c: wtf, timer poped up and there is no packet to dequeue\n");
		(*hlp_functions->dequeue_timer) (p->priv->t[p->dir]);
		return 0;
	}

	ndprint("helper_tcp.c: 0x%x-%u, warning, timer expired for missing segment. processing anyway. lost %u bytes cp = 0x%x, seq %u, expected %u\n", (unsigned) p->priv->pkts[p->dir]->f->ce, p->dir, p->priv->seq_expected[p->dir] - p->priv->last_seq[p->dir], (unsigned) p->priv, p->priv->last_seq[p->dir], p->priv->seq_expected[p->dir]);
	return helper_process_next_tcp(p->priv, p->dir);

}

int helper_process_next_tcp(struct helper_priv_tcp *p, int dir) {


	struct helper_priv_tcp_packet *pkt = p->pkts[dir];

	p->pkts[dir] = p->pkts[dir]->next;

	if (p->pkts[dir]) {
		p->pkts[dir]->prev = NULL;

		if (!p->pkts[dir]->next)
			p->pkts_tail[dir] = p->pkts[dir];
	} else 
		p->pkts_tail[dir] = NULL;

	p->buff_len[dir] -= pkt->f->len;
	p->seq_expected[dir] = pkt->seq;

	if (p->t[dir]) {
		(*hlp_functions->dequeue_timer) (p->t[dir]);

		if (p->pkts[dir]) {
			(*hlp_functions->queue_timer) (p->t[dir], PTYPE_UINT32_GETVAL(pkt_timeout));
		}
	}
	ndprint("helper_tcp.c: %u.%u 0x%x-%u, dequeuing packet with seq %u, bufflen is %d\n", (unsigned)pkt->f->tv.tv_sec, (unsigned)pkt->f->tv.tv_usec, (unsigned) pkt->f->ce, dir, pkt->seq, p->buff_len[dir]);
	(*hlp_functions->queue_frame) (pkt->f);

	free(pkt);

	return H_OK;
}


int helper_flush_buffer_tcp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_tcp *cp = conntrack_priv;

	if (cp->pkts[0]) {
		helper_process_next_tcp(cp, 0);
		return H_OK;
	}

	if (cp->pkts[1]) {
		helper_process_next_tcp(cp, 1);
		return H_OK;
	}

	return H_ERR;
}

int helper_cleanup_connection_tcp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_tcp *cp = conntrack_priv;

#ifdef DEBUG
	if (cp->pkts[0] || cp->pkts[1]) {
		dprint("helper_tcp : There should not be any remaining packet at this point !!!!\n");
		int i;
		for (i = 0; i < 2; i++)
			while (cp->pkts[i]) {
				struct helper_priv_tcp_packet *pkt = cp->pkts[i];
				cp->pkts[i] = cp->pkts[i]->next;
				free(pkt->f->buff);
				free(pkt->f);
				free(pkt);
			}
	}
#endif

	if (cp->t[0]) {
		free (cp->t[0]->priv);
		(*hlp_functions->cleanup_timer) (cp->t[0]);
		cp->t[0] = NULL;
	}

	if (cp->t[1]) {
		free (cp->t[1]->priv);
		(*hlp_functions->cleanup_timer) (cp->t[1]);
		cp->t[1] = NULL;
	}


	if (cp->prev)
		cp->prev->next = cp->next;
	else
		conn_head = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;
		
	free(cp);

	return H_OK;
}

int helper_cleanup_tcp() {

	while (conn_head) {
		(hlp_functions->conntrack_remove_priv) (conn_head, conn_head->ce);	
		helper_cleanup_connection_tcp(conn_head->ce, conn_head);
	}

	(hlp_functions->ptype_cleanup) (pkt_timeout);
	(hlp_functions->ptype_cleanup) (conn_buff);
	return H_OK;
}

