/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2009 Guy Martin <gmsoft@tuxicoman.be>
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
#include "ptype_bool.h"

#define __FAVOR_BSD // We use BSD favor of the tcp header
#include <netinet/tcp.h>

#if 0 
#define tcp_tshoot(x...) pom_log(POM_LOG_TSHOOT x)
#else
#define tcp_tshoot(x...)
#endif

static struct ptype *pkt_timeout;
static struct ptype *conn_buff;
static struct ptype *fill_gaps;

// Helps to track all the connections
static struct helper_priv_tcp *conn_head;

static int match_tcp_id, match_undefined_id;

int helper_register_tcp(struct helper_reg *r) {
	
	r->need_help = helper_need_help_tcp;
	r->cleanup = helper_cleanup_tcp;

	pkt_timeout = ptype_alloc("uint32", "seconds");
	conn_buff = ptype_alloc("uint32", "KBytes");
	fill_gaps = ptype_alloc("bool", NULL);

	if (!pkt_timeout || !conn_buff || !fill_gaps)
		goto err;

	helper_register_param(r->type, "pkt_timeout", "30", pkt_timeout, "Number of seconds to wait for out of order packets");
	helper_register_param(r->type, "conn_buffer", "64", conn_buff, "Maximum KBytes of buffer per connection");
	helper_register_param(r->type, "fill_gaps", "yes", fill_gaps, "Fill gaps in connections with empty packets");

	conn_head = NULL;

	match_tcp_id = r->type;
	match_undefined_id = match_register("undefined");

	return POM_OK;

err:

	ptype_cleanup(pkt_timeout);
	ptype_cleanup(conn_buff);
	return POM_ERR;

}

static int helper_need_help_tcp(struct frame *f, unsigned int start, unsigned int len, struct layer *l) {


	struct tcphdr* hdr = f->buff + start;
	int payload_size = l->payload_size;


	// We need to track all the tcp packets
	if (!f->ce)
		if (conntrack_get_entry(f) == POM_ERR)
			if (conntrack_create_entry(f) == POM_ERR)
				return POM_OK;
	
	uint32_t new_seq, new_ack;
	new_seq = ntohl(hdr->th_seq);
	new_ack = ntohl(hdr->th_ack);

	tcp_tshoot("Got packet %u -> %u", new_seq, new_seq + payload_size);

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
	
		if (!payload_size) // We don't need to reorder empty packets
			return POM_OK;


		if (new_seq + payload_size <= cp->seq_expected[dir]) {
			tcp_tshoot("Discarded, duplicate of already processed payload : expected seq %u", cp->seq_expected[dir]);
			return H_NEED_HELP;
		} else if (new_seq > cp->seq_expected[dir]) {
		

			struct helper_priv_tcp_packet *tmp_pkt = cp->pkts[dir];

			// If there is something in the queue, let's see where to put our packet
			// Go up to seq of packet in the queue is >= to the current one
			while (tmp_pkt && tmp_pkt->seq < new_seq) 
				tmp_pkt = tmp_pkt->next;

			if (tmp_pkt) {
				if ((tmp_pkt->seq >= new_seq) && (tmp_pkt->seq + tmp_pkt->data_len <= new_seq + payload_size)) {
					// same payload size -> we can safely discard it
					tcp_tshoot("Discarded, duplicate of packet already in the queue : %u -> %u", tmp_pkt->seq, tmp_pkt->seq + tmp_pkt->data_len);
					return H_NEED_HELP;
				} else if ((tmp_pkt->seq == new_seq) && (tmp_pkt->data_len < payload_size)) {
					tcp_tshoot("Replacing smaller packet from the queue : %u -> %u", tmp_pkt->seq, tmp_pkt->seq + tmp_pkt->data_len);

					cp->buff_len[dir] += payload_size - tmp_pkt->data_len;

					free(tmp_pkt->f->buff_base);

					memcpy(tmp_pkt->f, f, sizeof(struct frame));
					frame_alloc_aligned_buff(tmp_pkt->f, f->len);
					memcpy(tmp_pkt->f->buff, f->buff, f->len);
					tmp_pkt->seq = new_seq;
					tmp_pkt->ack = new_ack;
					tmp_pkt->data_len = payload_size;
					return H_NEED_HELP;
				}

			}
				

			// At this point we need to queue the packet before tmp_pkt or at the end of the list if tmp_pkt == NULL

			tcp_tshoot("Queuing packet");

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
				if (PTYPE_BOOL_GETVAL(fill_gaps)) {
					tcp_tshoot("Buffer reached treshold : %u. Filling gap", cp->buff_len[dir]);
					if (helper_fill_gap_tcp(f, l, cp->seq_expected[dir], cp->pkts[dir]->seq - cp->seq_expected[dir]) == POM_ERR)
						 helper_process_next_tcp(cp, dir);
				} else {
					tcp_tshoot("Buffer reached treshold : %u. Processing next packet", cp->buff_len[dir]);
					helper_process_next_tcp(cp, dir);
				}
			}
			return H_NEED_HELP;

		} else if (new_seq < cp->seq_expected[dir]) { // We must discard some of the begining of the packet

			int pos = cp->seq_expected[dir] - new_seq;
			int new_len = payload_size - pos;

			tcp_tshoot("Discarding %u bytes at the begining of the packet", pos);


			char *pload = f->buff + l->payload_start;

			memmove(pload, pload + pos, new_len);
			hdr->th_seq = htonl(cp->seq_expected[dir]);
			new_seq = cp->seq_expected[dir];

			helper_resize_payload(f, l, new_len);
			f->len -= pos;
			payload_size = new_len;
		}


	} else {

		if (hdr->th_flags & TH_RST) {
			// Don't learn initial sequence from RST packets as it's often bogus (0)
			tcp_tshoot("Ignoring sequence from RST packet and processing it");
			return POM_OK;
		}

		cp->flags[dir] |= HELPER_TCP_SEQ_KNOWN;
		struct helper_timer_priv_tcp *tmp = malloc(sizeof(struct helper_timer_priv_tcp));
		memset(tmp, 0, sizeof(struct helper_timer_priv_tcp));
		tmp->priv = cp;
		tmp->dir = dir;
		cp->t[dir] = timer_alloc(tmp, f->input, helper_process_timer_tcp);
	}

	cp->seq_expected[dir] = new_seq + payload_size;
	if (hdr->th_flags & TH_SYN || hdr->th_flags & TH_FIN)
		cp->seq_expected[dir]++;

	tcp_tshoot("Processing packet");

	// Discard any packet that we are sure not to need anymore
	while (cp->pkts[dir] && ((cp->pkts[dir]->seq + cp->pkts[dir]->data_len) < cp->seq_expected[dir])) {
		tcp_tshoot("Discarding useless packet packet from the queue : %u -> %u", cp->pkts[dir]->seq, cp->pkts[dir]->seq + cp->pkts[dir]->data_len);
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

		if (cp->pkts[dir]->seq == cp->seq_expected[dir]) {
			tcp_tshoot("Processing next packet from the queue, exact match : %u -> %u", cp->pkts[dir]->seq, cp->pkts[dir]->seq + cp->pkts[dir]->data_len);
			// It's easy, the sequence number match !
			helper_process_next_tcp(cp, dir);
		} else if (cp->pkts[dir]->seq < cp->seq_expected[dir] && // packet must be before what we expect
				cp->pkts[dir]->seq + cp->pkts[dir]->data_len >= cp->seq_expected[dir]) {
			// Looks like we need already have data from this packet in the buffer
			unsigned int dup_data_len = cp->seq_expected[dir] - cp->pkts[dir]->seq;
			tcp_tshoot("Discarding %u of data over %u from current packet and processing it : %u -> %u", dup_data_len, payload_size, cp->pkts[dir]->seq, cp->pkts[dir]->seq + l->payload_size - dup_data_len);
			helper_resize_payload(f, l, l->payload_size - dup_data_len);
			f->len -= dup_data_len;
			helper_process_next_tcp(cp, dir);
		}
		
	}

	return POM_OK;
}

static int helper_process_timer_tcp(void *priv) {

	struct helper_timer_priv_tcp *p = priv;
	if (!p->priv->pkts[p->dir]) {
		pom_log(POM_LOG_WARN "Timer poped up and there is no packet to dequeue");
		timer_dequeue(p->priv->t[p->dir]);
		return POM_OK;
	}

	int result = POM_OK;
	if (PTYPE_BOOL_GETVAL(fill_gaps)) {
		tcp_tshoot("Timer fired, filling gap");
		if (helper_fill_gap_no_layer_tcp(p->priv->pkts[p->dir]->f, p->priv->seq_expected[p->dir], p->priv->pkts[p->dir]->seq - p->priv->seq_expected[p->dir]) == POM_OK) {
			timer_dequeue(p->priv->t[p->dir]);
			timer_queue(p->priv->t[p->dir], PTYPE_UINT32_GETVAL(pkt_timeout));
		} else {
			result = helper_process_next_tcp(p->priv, p->dir);
		}
	} else {
		tcp_tshoot("Timer fired, processing next packet");
		result = helper_process_next_tcp(p->priv, p->dir);
	}
	return result;

}

static int helper_fill_gap_no_layer_tcp(struct frame *f, uint32_t seq_init, unsigned int gap_size) {
	// Layer information was lost, we need to compute it again
	// No need to do lots of checking since it was already done in do_rule before
	// WARNING : this means that TCP into TCP connection won't work

	layer_pool_discard();

	struct layer *l = layer_pool_get();
	l->type = f->first_layer;
	layer_field_pool_get(l);
	f->l = l;
	int new_start = 0, new_len = f->len;
	while (l && l->type != match_tcp_id) {
		l->next = layer_pool_get();
		l->next->prev = l;
		if (l->prev) {
			new_start = l->prev->payload_start;
			new_len = l->prev->payload_size;
		}

		// identify must populate payload_start and payload_size
		l->next->type = match_identify(f, l, new_start, new_len);
		if (l->next->type == POM_ERR || l->next->type == match_undefined_id) {
			tcp_tshoot("Unable to identify the TCP packet !!!");
			return POM_ERR;
		}
		layer_field_pool_get(l->next);

		l = l->next;
	}

	if (l->prev) {
		new_start = l->prev->payload_start;
		new_len = l->prev->payload_size;
	}
	match_identify(f, l, new_start, new_len);

	return helper_fill_gap_tcp(f, l, seq_init, gap_size);
}

static int helper_fill_gap_tcp(struct frame *f, struct layer *l, uint32_t seq_init, unsigned int gap_size) {


	if (gap_size > PTYPE_UINT32_GETVAL(conn_buff) * 1024) {
		tcp_tshoot("Gap size bigger than max connection buffer. Ignoring");
		return POM_ERR;
	}

	tcp_tshoot("Filling gap of %u bytes from sequence %u", gap_size, seq_init);

	unsigned int remaining = gap_size;

	unsigned int max = f->bufflen - l->payload_start;
	if (max < 1280) // minimum value for MTU
		max = 1280;

	while (remaining > 0) {

		// Alloc the frame
		struct frame *fgap = malloc(sizeof(struct frame));
		memcpy(fgap, f, sizeof(struct frame));

		unsigned int cur;
		if (remaining > max) {
			cur = max;
			remaining -= cur;
		} else {
			cur = remaining;
			remaining = 0;
		}


		// Alloc the frame payload
		frame_alloc_aligned_buff(fgap, l->payload_start + cur);

		// Copy headers
		memcpy(fgap->buff, f->buff, l->payload_start);
		memset(fgap->buff + l->payload_start, 0, cur);

		int start = 0;
		if (l->prev)
			start = l->prev->payload_start;

		struct tcphdr *hdr = fgap->buff + start;
		hdr->th_seq = htonl(seq_init);

		// Clear SYN/FIN/RST packet
		hdr->th_flags &= ~(TH_SYN | TH_FIN | TH_RST);

		if (helper_resize_payload(fgap, l, cur) == POM_ERR)
			return POM_ERR;

		fgap->len = l->payload_start + cur;

		helper_queue_frame(fgap);

		seq_init += cur;

	}

	return POM_OK;

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
	tcp_tshoot("Dequeuing packet : %u -> %u", pkt->seq, pkt->seq + pkt->seq + pkt->data_len);
	helper_queue_frame(pkt->f);

	free(pkt);

	return POM_OK;
}


static int helper_flush_buffer_tcp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_tcp *cp = conntrack_priv;

	int i;
	for (i = 0; i <= 1; i++ ) {
		if (cp->pkts[i]) {
			
			if (PTYPE_BOOL_GETVAL(fill_gaps) &&
				(helper_fill_gap_no_layer_tcp(cp->pkts[i]->f, cp->seq_expected[i], cp->pkts[i]->seq - cp->seq_expected[i]) == POM_OK)) {
				timer_dequeue(cp->t[i]);
				timer_queue(cp->t[i], PTYPE_UINT32_GETVAL(pkt_timeout));
			} else {
				helper_process_next_tcp(cp, i);
			}
			return POM_OK;
		}
	}

	return POM_ERR;
}

static int helper_cleanup_connection_tcp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_tcp *cp = conntrack_priv;

	if (cp->pkts[0] || cp->pkts[1]) {
		pom_log(POM_LOG_DEBUG "There should not be any remaining packet at this point !!!!");
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
	ptype_cleanup(fill_gaps);
	return POM_OK;
}

