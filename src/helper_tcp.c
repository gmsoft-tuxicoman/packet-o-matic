/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2008 Guy Martin <gmsoft@tuxicoman.be>
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

#include "ptype_uint32.h"

#define __FAVOR_BSD // We use BSD favor of the tcp header
#include <netinet/tcp.h>

static struct ptype *pkt_timeout;
static struct ptype *conn_buff;

// Helps to track all the connections
static struct helper_priv_tcp *conn_head;

int helper_register_tcp(struct helper_reg *r) {
	
	r->need_help = helper_need_help_tcp;
	r->cleanup = helper_cleanup_tcp;

	pkt_timeout = ptype_alloc("uint32", "seconds");
	conn_buff = ptype_alloc("uint32", "KBytes");

	if (!pkt_timeout || !conn_buff)
		goto err;

	helper_register_param(r->type, "pkt_timeout", "30", pkt_timeout, "Number of seconds to wait for out of order packets");
	helper_register_param(r->type, "conn_buffer", "256", conn_buff, "Maximum KBytes of buffer per connection");

	conn_head = NULL;

	return POM_OK;

err:

	ptype_cleanup(pkt_timeout);
	ptype_cleanup(conn_buff);
	return POM_ERR;

}

static int helper_need_help_tcp(struct frame *f, unsigned int start, unsigned int len, struct layer *l) {


	struct tcphdr* hdr = f->buff + start;
	int payload_size = l->payload_size;

	if (!payload_size) // We don't need to reorder empty packets
		return POM_OK;

	// We need to track all the tcp packets
	if (!f->ce)
		if (conntrack_get_entry(f) == POM_ERR)
			if (conntrack_create_entry(f) == POM_ERR)
				return POM_OK;
	
	uint32_t new_seq, new_ack;
	new_seq = ntohl(hdr->th_seq);
	new_ack = ntohl(hdr->th_ack);

	struct helper_priv_tcp *cp = conntrack_get_helper_priv(l->type, f->ce);
	if (!cp) {
		// We don't know anything about this connection. let it go
		cp = malloc(sizeof(struct helper_priv_tcp));
		memset(cp, 0, sizeof(struct helper_priv_tcp));

		cp->ce = f->ce;

		if (!conn_head)
			conn_head = cp;
		else {
			cp->next = conn_head;
			cp->next->prev = cp;
			conn_head = cp;
		}

		conntrack_add_helper_priv(cp, l->type, f->ce, helper_flush_buffer_tcp, helper_cleanup_connection_tcp);
	}

	int dir = f->ce->direction;

	if (cp->flags[dir] & HELPER_TCP_SEQ_KNOWN) {
	
		if (new_seq + payload_size < cp->seq_expected[dir]) {
			//pom_log(POM_LOG_TSHOOT "helper_tcp.c: %u.%u 0x%x-%u, expected seq %u < got seq %u, bufflen is %d. discarding packet", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, cp->seq_expected[dir], new_seq, cp->buff_len[dir]);
			return H_NEED_HELP;
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
									//pom_log(POM_LOG_TSHOOT "helper_tcp.c: %u.%u 0x%x-%u, got seq %u, bufflen is %d. discarding duplicate already in the queue", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, new_seq, cp->buff_len[dir]);
									return H_NEED_HELP;
								} else {
									//pom_log(POM_LOG_TSHOOT "helper_tcp.c: %u.%u 0x%x-%u, got seq %u, bufflen is %d. replacing duplicate already in the queue", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, new_seq, cp->buff_len[dir]);
									cp->buff_len[dir] += payload_size - tmp_pkt->data_len;

									free(tmp_pkt->f->buff_base);
									free(tmp_pkt->f);
									tmp_pkt->f = malloc(sizeof(struct frame));
									memcpy(tmp_pkt->f, f, sizeof(struct frame));
									frame_alloc_aligned_buff(tmp_pkt->f, f->len);
									memcpy(tmp_pkt->f->buff, f->buff, f->len);
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
			//pom_log(POM_LOG_TSHOOT "helper_tcp.c: %u.%u 0x%x-%u, expected seq %u > got seq %u, bufflen is %d. queuing packet", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, cp->seq_expected[dir], new_seq, cp->buff_len[dir]);

			struct helper_priv_tcp_packet *pkt = malloc(sizeof(struct helper_priv_tcp_packet));
			memset(pkt, 0, sizeof(struct helper_priv_tcp_packet));

			// This will be fred by the helper subsystem
			pkt->f = malloc(sizeof(struct frame));
			memcpy(pkt->f, f, sizeof(struct frame));
			frame_alloc_aligned_buff(pkt->f, f->len);
			memcpy(pkt->f->buff, f->buff, f->len);
			
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
					timer_queue(cp->t[dir], PTYPE_UINT32_GETVAL(pkt_timeout));
				}

			}


			
			cp->buff_len[dir] += f->len;


			// Maybe we suffer from packet loss. Default maximum buffer is 256 KBytes 
			if (cp->buff_len[dir] > PTYPE_UINT32_GETVAL(conn_buff) * 1024) {
				//pom_log(POM_LOG_TSHOOT "helper_tcp.c: 0x%x-%u, warning, buffer is too large : %u. we probably lost a packet. processing anyway. lost %u bytes cp = 0x%x, seq %u, expected %u", (unsigned) f->ce, dir, cp->buff_len[dir], cp->seq_expected[dir] - cp->last_seq[dir], (unsigned) cp, cp->last_seq[dir], cp->seq_expected[dir]);
				helper_process_next_tcp(cp, dir);
			}

			return H_NEED_HELP;
		}


	} else {
		cp->flags[dir] |= HELPER_TCP_SEQ_KNOWN;
		struct helper_timer_priv_tcp *tmp = malloc(sizeof(struct helper_timer_priv_tcp));
		memset(tmp, 0, sizeof(struct helper_timer_priv_tcp));
		tmp->priv = cp;
		tmp->dir = dir;
		cp->t[dir] = timer_alloc(tmp, f->input, helper_process_timer_tcp);
	}

	cp->last_seq[dir] = new_seq;
	
	cp->seq_expected[dir] = new_seq + payload_size;
	if (hdr->th_flags & TH_SYN || hdr->th_flags & TH_FIN)
		cp->seq_expected[dir]++;

	//pom_log(POM_LOG_TSHOOT "helper_tcp.c: %u.%u 0x%x-%u, got seq %u, new expected seq %u, bufflen is %d. processing packet", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, new_seq, cp->seq_expected[dir], cp->buff_len[dir]);

	// Discard any packet that we are sure not to need anymore
	while (cp->pkts[dir] && ((cp->pkts[dir]->seq + cp->pkts[dir]->data_len) < cp->seq_expected[dir])) {
		//pom_log(POM_LOG_TSHOOT "helper_tcp.c: 0x%x-%u, discarding packet with seq %u from queue", (unsigned) f->ce, dir, cp->pkts[dir]->seq);
		struct helper_priv_tcp_packet *pkt = cp->pkts[dir];
		cp->pkts[dir] = cp->pkts[dir]->next;
		if (cp->pkts[dir]) {
			cp->pkts[dir]->prev = NULL;
		} else {
			timer_dequeue(cp->t[dir]);
			cp->pkts_tail[dir] = NULL;
		}
		cp->buff_len[dir] -= pkt->f->len;
		free(pkt->f->buff_base);
		free(pkt->f);
		free(pkt);

	}

	// Let's see if we can dequeue the next packets now
	if (cp->pkts[dir]) {
		//pom_log(POM_LOG_TSHOOT"helper_tcp.c: %u.%u 0x%x-%u, expected seq %u, first packet in queue seq %u", (unsigned)f->tv.tv_sec, (unsigned)f->tv.tv_usec, (unsigned) f->ce, dir, cp->seq_expected[dir], cp->pkts[dir]->seq);
		if (cp->pkts[dir]->seq == cp->seq_expected[dir]) {
			// It's easy, the sequence number match !
			helper_process_next_tcp(cp, dir);
		} else if (cp->pkts[dir]->seq < cp->seq_expected[dir] && // packet must be before what we expect
				cp->pkts[dir]->seq + cp->pkts[dir]->data_len >= cp->seq_expected[dir] && 
				(!cp->pkts[dir]->next || cp->pkts[dir]->seq + cp->pkts[dir]->data_len < cp->pkts[dir]->next->seq + cp->pkts[dir]->next->data_len)) {
			// Looks like we need already have data from this packet in the buffer
			unsigned int dup_data_len = cp->seq_expected[dir] - cp->pkts[dir]->seq;
			//pom_log(POM_LOG_TSHOOT "helper_tcp.c: 0x%x-%u, need to drop %u of data over %u from current packet", (unsigned) f->ce, dir, dup_data_len, payload_size);
			l->payload_size -= dup_data_len;
			helper_process_next_tcp(cp, dir);
		}
		
	}
/*
	if (cp->t[dir] && cp->pkts[dir]) {
		timer_dequeue(cp->t[dir]);
		timer_queue(cp->t[dir], PTYPE_UINT32_GETVAL(pkt_timeout));
	}
*/
	return POM_OK;
}

static int helper_process_timer_tcp(void *priv) {

	struct helper_timer_priv_tcp *p = priv;
	if (!p->priv->pkts[p->dir]) {
		pom_log(POM_LOG_WARN "helper_tcp.c: wtf, timer poped up and there is no packet to dequeue");
		timer_dequeue(p->priv->t[p->dir]);
		return POM_OK;
	}

	//pom_log(POM_LOG_TSHOOT "helper_tcp.c: 0x%x-%u, warning, timer expired for missing segment. processing anyway. lost %u bytes cp = 0x%x, seq %u, expected %u", (unsigned) p->priv->pkts[p->dir]->f->ce, p->dir, p->priv->seq_expected[p->dir] - p->priv->last_seq[p->dir], (unsigned) p->priv, p->priv->last_seq[p->dir], p->priv->seq_expected[p->dir]);
	return helper_process_next_tcp(p->priv, p->dir);

}

static int helper_process_next_tcp(struct helper_priv_tcp *p, int dir) {


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
		timer_dequeue(p->t[dir]);

		if (p->pkts[dir]) {
			timer_queue(p->t[dir], PTYPE_UINT32_GETVAL(pkt_timeout));
		}
	}
	//pom_log(POM_LOG_TSHOOT "helper_tcp.c: %u.%u 0x%x-%u, dequeuing packet with seq %u, bufflen is %d", (unsigned)pkt->f->tv.tv_sec, (unsigned)pkt->f->tv.tv_usec, (unsigned) pkt->f->ce, dir, pkt->seq, p->buff_len[dir]);
	helper_queue_frame(pkt->f);

	free(pkt);

	return POM_OK;
}


static int helper_flush_buffer_tcp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_tcp *cp = conntrack_priv;

	if (cp->pkts[0]) {
		helper_process_next_tcp(cp, 0);
		return POM_OK;
	}

	if (cp->pkts[1]) {
		helper_process_next_tcp(cp, 1);
		return POM_OK;
	}

	return POM_ERR;
}

static int helper_cleanup_connection_tcp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_tcp *cp = conntrack_priv;

	if (cp->pkts[0] || cp->pkts[1]) {
		pom_log(POM_LOG_DEBUG "helper_tcp : There should not be any remaining packet at this point !!!!");
		int i;
		for (i = 0; i < 2; i++)
			while (cp->pkts[i]) {
				struct helper_priv_tcp_packet *pkt = cp->pkts[i];
				cp->pkts[i] = cp->pkts[i]->next;
				free(pkt->f->buff_base);
				free(pkt->f);
				free(pkt);
			}
	}

	if (cp->t[0]) {
		free (cp->t[0]->priv);
		timer_cleanup(cp->t[0]);
		cp->t[0] = NULL;
	}

	if (cp->t[1]) {
		free (cp->t[1]->priv);
		timer_cleanup(cp->t[1]);
		cp->t[1] = NULL;
	}


	if (cp->prev)
		cp->prev->next = cp->next;
	else
		conn_head = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;
		
	free(cp);

	return POM_OK;
}

static int helper_cleanup_tcp() {

	while (conn_head) {
		conntrack_remove_helper_priv(conn_head, conn_head->ce);	
		helper_cleanup_connection_tcp(conn_head->ce, conn_head);
	}

	ptype_cleanup(pkt_timeout);
	ptype_cleanup(conn_buff);
	return POM_OK;
}

