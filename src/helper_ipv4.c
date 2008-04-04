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

#include "helper_ipv4.h"

#include "ptype_uint32.h"

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#ifdef HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif

#define IP_DONT_FRAG 0x4000
#define IP_MORE_FRAG 0x2000
#define IP_OFFSET_MASK 0x1fff


struct helper_priv_ipv4 *frags_head;
struct helper_functions *hf;

struct ptype *frag_timeout;

int helper_register_ipv4(struct helper_reg *r, struct helper_functions *hlp_funcs) {
	
	r->need_help = helper_need_help_ipv4;
	r->cleanup = helper_cleanup_ipv4;

	hf = hlp_funcs;
	frags_head = NULL;

	frag_timeout = (*hlp_funcs->ptype_alloc) ("uint32", "seconds");
	if (!frag_timeout)
		return POM_ERR;
	(*hlp_funcs->register_param) (r->type, "frag_timeout", "60", frag_timeout, "Number of seconds to wait for subsequent packets");

	return POM_OK;
}


int helper_ipv4_process_frags(struct helper_priv_ipv4 *p) {

	struct frame *f = p->f;

	struct helper_priv_ipv4_frag *frg = p->frags;
	int pos = f->bufflen;

	// Calculate the total size of the new packet
	while (frg) {
		f->bufflen += frg->len;
		frg = frg->next;
	}

	f->len = f->bufflen;

	frg = p->frags;
	while (frg) {
		memcpy(f->buff + pos, frg->buffer, frg->len);
		pos += frg->len;
		frg = frg->next;
	}

	struct ip *hdr = (struct ip*) (f->buff + p->hdr_offset);

	hdr->ip_off = 0;
	hdr->ip_id = 0;
	hdr->ip_len = htons(f->bufflen - p->hdr_offset);


	(*hf->pom_log) (POM_LOG_TSHOOT "Helper ipv4 : sending packet to rule processor. len %u, first_layer %u\r\n", f->bufflen, f->first_layer);

	(*hf->queue_frame) (f);

	p->f = NULL;

	helper_cleanup_ipv4_frag(p);

	return POM_OK;


}

int helper_need_help_ipv4(struct frame *f, unsigned int start, unsigned int len, struct layer *l) {


	struct ip* hdr;
	hdr = f->buff + start;

	u_short frag_off = ntohs(hdr->ip_off);


	// No help needed if the don't fragment bit is set
	if (frag_off & IP_DONT_FRAG)
		return POM_OK;

	// We don't need to look at the packet if there are no more frags and it's an unfragmented packet
	// This imply MF -> 0 and offset = 0
	if (!(frag_off & IP_MORE_FRAG) && !(frag_off & IP_OFFSET_MASK))
		return POM_OK;

	u_short offset = (frag_off & IP_OFFSET_MASK) << 3;

	// Let's find the right buffer
	
	struct helper_priv_ipv4 *tmp = frags_head;


	while (tmp) {
		struct ip *tmphdr = (struct ip*) (tmp->f->buff + tmp->hdr_offset);
	        if (hdr->ip_src.s_addr == tmphdr->ip_src.s_addr
	                && hdr->ip_dst.s_addr == tmphdr->ip_dst.s_addr
	                && hdr->ip_id == tmphdr->ip_id)
			// Positive match we 've got it
			break;
		tmp = tmp->next;
	}
	unsigned int frag_start = start + (hdr->ip_hl * 4); // Make it the start of the payload
	size_t frag_size = ntohs(hdr->ip_len) - (hdr->ip_hl * 4);
	
	// Ignore invalid fragments
	if (frag_size > 0xFFFF)
		return POM_ERR;

	if (frag_start + frag_size > len + start) {
		(*hf->pom_log) (POM_LOG_DEBUG "Error, packet len missmatch dropping this frag : ipv4 [");
		int i;
		for (i = 0; i < MAX_LAYER_FIELDS && l->fields[i]; i++) {
			struct match_field_reg *field = (*hf->match_get_field) (l->type, i);
			if (!field)
				break;

			char buff[2048];
			if((*hf->ptype_print_val) (l->fields[i], buff, sizeof(buff)))
				(*hf->pom_log) (POM_LOG_DEBUG "%s: %s, ", field->name, buff);
		}
		(*hf->pom_log) (POM_LOG_DEBUG "frag_off: 0x%X, id: %u, frag_start: %u, frag_size: %u, size: %u]\r\n", frag_off, ntohs(hdr->ip_id), frag_start, (unsigned int) frag_size, l->prev->payload_size);

		return POM_ERR;
	}

	if (!tmp) {
		// Looks like the buffer wasn't found. Let's create it
		

		tmp = malloc(sizeof(struct helper_priv_ipv4));
		bzero(tmp,  sizeof(struct helper_priv_ipv4));
		tmp->next = frags_head;
		if (tmp->next)
			tmp->next->prev = tmp;
		frags_head = tmp;

		// Save the sublayer (ethernet or else) up to the start of the IPv4 payload
		tmp->f = malloc(sizeof(struct frame));
		memcpy(tmp->f, f, sizeof(struct frame));
		(*hf->frame_alloc_aligned_buff) (f, frag_start);
		tmp->f->len = frag_start;
		tmp->hdr_offset = start;

		(*hf->pom_log) (POM_LOG_TSHOOT "Helper ipv4 : allocated buffer for new packet id %u\r\n", ntohs(hdr->ip_id));
		tmp->t = (*hf->alloc_timer) (tmp, f->input, helper_cleanup_ipv4_frag);


	} else  // Remove this from the timer queue 
		(*hf->dequeue_timer) (tmp->t);

	// Reschedule the timer
	(*hf->queue_timer) (tmp->t, PTYPE_UINT32_GETVAL(frag_timeout));



	// Now let's find if we already have this fragment in memory

	struct helper_priv_ipv4_frag *fp = tmp->frags;

	while (fp) {
		if (fp->offset == offset)
			return H_NEED_HELP; // We already have it

		if (fp->offset > offset) // The next fragment has a higher offset
			break;

		if (!fp->next) // We are at the end of the list
			break;

		fp = fp->next;
	}


	// At this point we don't have the fragment in memory yet. Let's add it
	
	(*hf->pom_log) (POM_LOG_TSHOOT "Helper ipv4 : adding fragment %u for id %u in memory (start %u, len %u)\r\n", offset, ntohs(hdr->ip_id), frag_start, (unsigned int) frag_size);

	struct helper_priv_ipv4_frag *ftmp = malloc(sizeof(struct helper_priv_ipv4_frag));
	bzero(ftmp, sizeof(struct helper_priv_ipv4_frag));
	ftmp->offset = offset;
	ftmp->buffer = malloc(frag_size);
	memcpy(ftmp->buffer, f->buff + frag_start, frag_size);
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
			if (!fp->prev) { // There is only one packet in the list
					if (fp->offset > offset) { // Let's see if we need to add it after or before this one
						// We add it before this one
						ftmp->next = fp;
						fp->prev = ftmp;
						tmp->frags = ftmp;
						
					} else {
						// We add it after this one
						fp->next = ftmp;
						ftmp->prev = fp;
					}

			} else {
				ftmp->prev = fp;
				fp->next = ftmp;
			}
		}

	} else
		tmp->frags = ftmp;

	
	// Do we have all the fragments in memory ?

	fp = tmp->frags;

	if (fp->offset != 0) {
		(*hf->pom_log) (POM_LOG_TSHOOT "Helper ipv4 : missing first fragment\r\n");
		return H_NEED_HELP; // We miss the first fragment
	}

	while (fp->next) {
		(*hf->pom_log) (POM_LOG_TSHOOT "Helper ipv4 : fragment offset %u, len %u\r\n", fp->next->offset, fp->next->len);
		if (fp->next->offset != (fp->len + fp->offset))
			return H_NEED_HELP; // Return if we miss a fragment
		fp = fp->next;
	}

	if (fp->last) {
		// We have the last fragment. Process the packet
		(*hf->pom_log) (POM_LOG_TSHOOT "Helper ipv4 : processing packet\r\n");
		helper_ipv4_process_frags(tmp);
		return H_NEED_HELP;

	}

	// We miss the last packet

	return H_NEED_HELP;
}

int helper_cleanup_ipv4_frag(void *priv) {

	struct helper_priv_ipv4 *p = priv;

	while (p->frags) {
		struct helper_priv_ipv4_frag *f;
		f = p->frags;
		free(f->buffer);
		p->frags = p->frags->next;
		free(f);
	}

	if (p->t) {
		(*hf->cleanup_timer) (p->t);
	}

	if (p->prev)
		p->prev->next = p->next;
	else
		frags_head = p->next;

	if (p->next)
		p->next->prev = p->prev;

	if (p->f) {
		free(p->f->buff_base);
		free(p->f);
	}
	free(p);

	return POM_OK;
}

int helper_cleanup_ipv4() {

	(*hf->ptype_cleanup) (frag_timeout);

	while (frags_head) {
/*		struct helper_priv_ipv4 *p = frags_head;
		free(p->f->buff_base);
		free(p->f);*/
		helper_cleanup_ipv4_frag(frags_head);
	}
	
	return POM_OK;
}

