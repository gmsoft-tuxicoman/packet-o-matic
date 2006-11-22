/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
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


#include <netinet/ip.h>

#include "helper_ipv4.h"

// 60 sec of fragmentation timeout
#define IP_FRAG_TIMEOUT 60

#define IP_DONT_FRAG 0x4000
#define IP_MORE_FRAG 0x2000
#define IP_OFFSET_MASK 0x1fff


struct helper_priv_ipv4 *frags_head;
struct helper_functions *hlp_functions;

int helper_register_ipv4(struct helper_reg *r, struct helper_functions *hlp_funcs) {
	
	r->need_help = helper_need_help_ipv4;
	r->cleanup = helper_cleanup_ipv4;

	hlp_functions = hlp_funcs;

	return 1;
}

int helper_init_ipv4() {

	frags_head = NULL;

	return 1;

}


int helper_ipv4_process_frags(struct helper_priv_ipv4 *p) {




	int pos = p->buffsize;
	char *buffer = malloc(pos);

	struct helper_priv_ipv4_frag *f = p->frags;

	while (f) {
		buffer = realloc(buffer, pos + f->len);
		memcpy(buffer + pos, f->buffer, f->len);
		pos += f->len;
		f = f->next;
	}


	p->hdr->frag_off = 0;
	p->hdr->id = 0;
	p->hdr->tot_len = htons(pos - p->buffsize);

	memcpy(buffer, p->sublayer_buff, p->buffsize);

	ndprint("Helper ipv4 : sending packet to rule processor. len %u, first_layer %u\n", pos, p->first_layer);

	(*hlp_functions->process_packet) (buffer, pos, p->first_layer);

	free(buffer);


	helper_cleanup_ipv4_frag(p);

	return 1;


}

int helper_need_help_ipv4(void *frame, struct match *m) {


	struct iphdr* hdr;
	unsigned int start = m->prev->next_start;

	if (!m->prev) {
		dprint("Helper ipv4 doesn't support raw ipv4\n");
		return 0;
	}

	hdr = frame + start;

	u_short frag_off = ntohs(hdr->frag_off);

	// No help needed if the don't fragment bit is set
	if (frag_off & IP_DONT_FRAG)
		return 0;

	// We don't need to look at the packet if there are no more frags and it's an unfragmented packet
	// This imply MF -> 0 and offset = 0
	if (!(frag_off & IP_MORE_FRAG) && !(frag_off & IP_OFFSET_MASK))
		return 0;

	u_short offset = (frag_off & IP_OFFSET_MASK) << 3;

	// Let's find the right buffer
	
	struct helper_priv_ipv4 *tmp = frags_head;

	ndprint("Helper ipv4 : Looking for frags with id %u\n", ntohs(hdr->id));

	while (tmp) {
		if (hdr->saddr == tmp->hdr->saddr
			&& hdr->daddr == tmp->hdr->daddr
			&& hdr->id == tmp->hdr->id)
			// Positive match we 've got it
			break;
		tmp = tmp->next;
	}


	if (!tmp) {
		// Looks like the buffer wasn't found. Let's create it
		

		tmp = malloc(sizeof(struct helper_priv_ipv4));
		bzero(tmp,  sizeof(struct helper_priv_ipv4));
		tmp->next = frags_head;
		if (tmp->next)
			tmp->next->prev = tmp;
		frags_head = tmp;

		ndprint("Helper ipv4 : allocated buffer for new packet id %u\n", ntohs(hdr->id));
		tmp->t = (*hlp_functions->alloc_timer) (tmp, helper_cleanup_ipv4_frag);


	} else { // Remove this from the timer queue 
		//ndprint("Helper ipv4 : frags with id %u found in memory\n", tmp->id);
		(*hlp_functions->dequeue_timer) (tmp->t);
	}

	// Reschedule the timer
	(*hlp_functions->queue_timer) (tmp->t, IP_FRAG_TIMEOUT);

	unsigned int frag_start = start + (hdr->ihl * 4); // Make it the start of the payload
	size_t frag_size = ntohs(hdr->tot_len) - (hdr->ihl * 4);

	if (start + frag_size > m->prev->next_size) {
		dprint("Error, packet len missmatch dropping this frag\n");
		return 1;
	}

	// Buffer the sublayer (ethernet or else) if this is the first packet of the segment with the IP header
	if (!tmp->sublayer_buff && offset == 0) {
		tmp->sublayer_buff = malloc(frag_start);
		memcpy(tmp->sublayer_buff, frame, frag_start);
		tmp->buffsize = frag_start;
		tmp->hdr = (struct iphdr *) (tmp->sublayer_buff + start);

		// Save the first layer type
		while (m->prev)
			m = m->prev;
		tmp->first_layer = m->match_type;
	}

	// Now let's find if we already have this fragment in memory

	struct helper_priv_ipv4_frag *fp = tmp->frags;

	while (fp) {
		if (fp->offset == offset)
			return 1; // We already have it

		if (fp->offset > offset) // The next fragment has a higher offset
			break;

		if (!fp->next) // We are at the end of the list
			break;

		fp = fp->next;
	}


	// At this point we don't have the fragment in memory yet. Let's add it
	
	ndprint("Helper ipv4 : adding fragment %u for id %u in memory (start %u, len %u)\n", offset, ntohs(tmp->hdr->id), frag_start, frag_size);

	struct helper_priv_ipv4_frag *ftmp = malloc(sizeof(struct helper_priv_ipv4_frag));
	bzero(ftmp, sizeof(struct helper_priv_ipv4_frag));
	ftmp->offset = offset;
	ftmp->buffer = malloc(frag_size);
	memcpy(ftmp->buffer, frame + frag_start, frag_size);
	ftmp->len = frag_size;
	if (!(frag_off & IP_MORE_FRAG))
		ftmp->last = 1;

	if (fp) { // We stopped somewhere in the fragment list
		if (fp->next) { // We are in the middle of the list
			ftmp->prev = fp->prev;
			if (!ftmp->prev)
				tmp->frags = ftmp;
			else
				ftmp->prev->next = ftmp;

			fp->prev = ftmp;
			ftmp->next = fp;
		} else { // We are at the end of the list
			ftmp->prev = fp;
			fp->next = ftmp;
		}

	} else
		tmp->frags = ftmp;

	
	// Do we have all the fragments in memory ?

	fp = tmp->frags;

	if (fp->offset != 0) {
		ndprint("Helper ipv4 : missing first fragment\n");
		return 1; // We miss the first fragment
	}

	while (fp->next) {
		ndprint("Helper ipv4 : fragment offset %u, len %u\n", fp->next->offset, fp->next->len);
		if (fp->next->offset != (fp->len + fp->offset))
			return 1; // Return if we miss a fragment
		fp = fp->next;
	}

	if (fp->last) {
		// We have the last fragment. Process the packet
		ndprint("Helper ipv4 : processing packet\n");
		helper_ipv4_process_frags(tmp);
		return 1;

	}

	// We miss the last packet

	return 1;
}

int helper_cleanup_ipv4_frag(void *priv) {

	struct helper_priv_ipv4 *p = priv;

	ndprint("Helper ipv4 : cleaning up fragments of id %u\n", ntohs(p->hdr->id));

	while (p->frags) {
		struct helper_priv_ipv4_frag *f;
		f = p->frags;
		free(f->buffer);
		p->frags = p->frags->next;
		free(f);
	}
	

	free(p->sublayer_buff);

	if (p->t) {
		(*hlp_functions->dequeue_timer) (p->t);
		(*hlp_functions->cleanup_timer) (p->t);
	}

	if (p->prev)
		p->prev->next = p->next;
	else
		frags_head = p->next;

	if (p->next)
		p->next->prev = p->prev;
	
	free(p);

	return 1;
}

int helper_cleanup_ipv4() {

	while (frags_head)
		helper_cleanup_ipv4_frag(frags_head);
	
	return 1;
}

