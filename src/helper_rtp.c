/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2008 Guy Martin <gmsoft@tuxicoman.be>
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

#include "helper_rtp.h"

#include "ptype_uint32.h"

#include "match_rtp.h"

struct ptype *pkt_timeout;
struct ptype *conn_buff;

// Helps to track all the connections
struct helper_priv_rtp *conn_head;

struct helper_functions *hf;
int helper_register_rtp(struct helper_reg *r, struct helper_functions *hlp_funcs) {
	
	r->need_help = helper_need_help_rtp;
	r->cleanup = helper_cleanup_rtp;

	hf = hlp_funcs;

	pkt_timeout = (*hlp_funcs->ptype_alloc) ("uint32", "seconds");
	conn_buff = (*hlp_funcs->ptype_alloc) ("uint32", "KBytes");

	if (!pkt_timeout || !conn_buff)
		goto err;

	(*hlp_funcs->register_param) (r->type, "pkt_timeout", "3", pkt_timeout, "Number of seconds to wait for out of order packets");
	(*hlp_funcs->register_param) (r->type, "conn_buffer", "80", conn_buff, "Maximum KBytes of buffer per connection");

	conn_head = NULL;

	return POM_OK;

err:

	(*hf->ptype_cleanup) (pkt_timeout);
	(*hf->ptype_cleanup) (conn_buff);
	return POM_ERR;

}

int helper_need_help_rtp(struct frame *f, unsigned int start, unsigned int len, struct layer *l) {


	struct rtphdr* hdr = f->buff + start;
	// We need to track all the rtp packets
	if (!f->ce)
		if ((*hf->conntrack_get_entry) (f) == POM_ERR)
			(*hf->conntrack_create_entry) (f);
	
	uint16_t new_seq;
	new_seq = ntohs(hdr->seq_num);

	struct helper_priv_rtp *cp = (*hf->conntrack_get_priv) (l->type, f->ce);
	if (!cp) {
		// We don't know anything about this connection. let it go
		cp = malloc(sizeof(struct helper_priv_rtp));
		memset(cp, 0, sizeof(struct helper_priv_rtp));

		cp->ce = f->ce;

		if (!conn_head)
			conn_head = cp;
		else {
			cp->next = conn_head;
			cp->next->prev = cp;
			conn_head = cp;
		}

		(*hf->conntrack_add_priv) (cp, l->type, f->ce, helper_flush_buffer_rtp, helper_cleanup_connection_rtp);
	}

	int dir = f->ce->direction;

	if (cp->flags[dir] & HELPER_RTP_SEQ_KNOWN) {
	
		if (new_seq + 1 < cp->seq_expected[dir]) {
			// We already have this packet
			return H_NEED_HELP;
		} else if (new_seq > cp->seq_expected[dir]) {
		

			struct helper_priv_rtp_packet *tmp_pkt = cp->pkts[dir];

			if (tmp_pkt) {
				// There is something in the queue
				// Let's see where to put our packet
				

				// Go up to seq of packet in the queue is >= to the current one
				while (tmp_pkt && tmp_pkt->seq < new_seq) 
					tmp_pkt = tmp_pkt->next;

				if (tmp_pkt && tmp_pkt->seq == new_seq) {

					// We got a packet with an existing seq in the queue, ignore it
					return H_NEED_HELP;
				}
				
			}

			// At this point we need to queue the packet before tmp_pkt or at the end of the list if empty

			struct helper_priv_rtp_packet *pkt = malloc(sizeof(struct helper_priv_rtp_packet));
			memset(pkt, 0, sizeof(struct helper_priv_rtp_packet));

			// This will be fred by the helper subsystem
			pkt->f = malloc(sizeof(struct frame));
			memcpy(pkt->f, f, sizeof(struct frame));
			(*hf->frame_alloc_aligned_buff) (pkt->f, f->len);
			memcpy(pkt->f->buff, f->buff, f->len);
			
			pkt->seq = new_seq;

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
					(*hf->queue_timer) (cp->t[dir], PTYPE_UINT32_GETVAL(pkt_timeout));
				}

			}


			
			cp->buff_len[dir] += f->len;


			// Maybe we suffer from packet loss. Default maximum buffer is 80 KBytes 
			if (cp->buff_len[dir] > PTYPE_UINT32_GETVAL(conn_buff) * 1024) {
				helper_process_next_rtp(cp, dir);
			}

			return H_NEED_HELP;
		}


	} else {
		cp->flags[dir] |= HELPER_RTP_SEQ_KNOWN;
		struct helper_timer_priv_rtp *tmp = malloc(sizeof(struct helper_timer_priv_rtp));
		memset(tmp, 0, sizeof(struct helper_timer_priv_rtp));
		tmp->priv = cp;
		tmp->dir = dir;
		cp->t[dir] = (*hf->alloc_timer) (tmp, f->input, helper_process_timer_rtp);
	}

	cp->seq_expected[dir] = new_seq + 1;

	// Let's see if we can dequeue the next packets now
	if (cp->pkts[dir] && cp->pkts[dir]->seq == cp->seq_expected[dir]) {
			// It's easy, the sequence number match !
			helper_process_next_rtp(cp, dir);
	}

	return POM_OK;
}

int helper_process_timer_rtp(void *priv) {

	struct helper_timer_priv_rtp *p = priv;
	if (!p->priv->pkts[p->dir]) {
		(*hf->pom_log) (POM_LOG_WARN "helper_rtp.c: wtf, timer poped up and there is no packet to dequeue\r\n");
		(*hf->dequeue_timer) (p->priv->t[p->dir]);
		return POM_OK;
	}

	return helper_process_next_rtp(p->priv, p->dir);

}

int helper_process_next_rtp(struct helper_priv_rtp *p, int dir) {


	struct helper_priv_rtp_packet *pkt = p->pkts[dir];

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
		(*hf->dequeue_timer) (p->t[dir]);

		if (p->pkts[dir]) {
			(*hf->queue_timer) (p->t[dir], PTYPE_UINT32_GETVAL(pkt_timeout));
		}
	}
	(*hf->queue_frame) (pkt->f);

	free(pkt);

	return POM_OK;
}


int helper_flush_buffer_rtp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_rtp *cp = conntrack_priv;

	if (cp->pkts[0]) {
		helper_process_next_rtp(cp, 0);
		return POM_OK;
	}

	if (cp->pkts[1]) {
		helper_process_next_rtp(cp, 1);
		return POM_OK;
	}

	return POM_ERR;
}

int helper_cleanup_connection_rtp(struct conntrack_entry *ce, void *conntrack_priv) {

	struct helper_priv_rtp *cp = conntrack_priv;

	if (cp->pkts[0] || cp->pkts[1]) {
		(*hf->pom_log) (POM_LOG_DEBUG "helper_rtp : There should not be any remaining packet at this point !!!!\r\n");
		int i;
		for (i = 0; i < 2; i++)
			while (cp->pkts[i]) {
				struct helper_priv_rtp_packet *pkt = cp->pkts[i];
				cp->pkts[i] = cp->pkts[i]->next;
				free(pkt->f->buff_base);
				free(pkt->f);
				free(pkt);
			}
	}

	if (cp->t[0]) {
		free (cp->t[0]->priv);
		(*hf->cleanup_timer) (cp->t[0]);
		cp->t[0] = NULL;
	}

	if (cp->t[1]) {
		free (cp->t[1]->priv);
		(*hf->cleanup_timer) (cp->t[1]);
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

int helper_cleanup_rtp() {

	while (conn_head) {
		(*hf->conntrack_remove_priv) (conn_head, conn_head->ce);	
		helper_cleanup_connection_rtp(conn_head->ce, conn_head);
	}

	(*hf->ptype_cleanup) (pkt_timeout);
	(*hf->ptype_cleanup) (conn_buff);
	return POM_OK;
}

