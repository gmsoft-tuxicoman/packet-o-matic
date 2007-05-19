/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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


#include "rules.h"
#include "helper.h"

int match_undefined_id;


int rules_init() {

	match_undefined_id = match_register("undefined");

	return 1;

}

inline int node_match(void *frame, unsigned int start, unsigned int len, struct rule_node *n, struct layer *l) {

	if (!l)
		return 0;

	struct match *m = n->match;

	int result = 1;

	struct layer *next_layer = l->next;

	if (m) {

		// The current layer is not identified. Let's see if we can match with the current match type
		if (l->type == match_undefined_id) {
			if (!l->prev) {
				ndprint("Error, first layer is undefined !\n");
				return 0;
			}
			unsigned int next_layer;
			l->type = m->type;
			next_layer = match_identify(l, frame, l->prev->payload_start, l->prev->payload_size);
			if (next_layer < 0) {
				// restore the original value
				l->type = match_undefined_id;
				return 0;
			} else {
				l->infos = layer_info_pool_get(l);
				l->next = layer_pool_get();
				l->next->type = next_layer;

				if (helper_need_help(l, frame, l->prev->payload_start, l->prev->payload_size)) // If it needs help, we don't process it
					return 0;
			
				// check the calculated size and adjust the max len of the packet
				// the initial size may be too long as some padding could have been introduced by the input

				if (l->prev && (l->payload_start + l->payload_size > l->prev->payload_start + l->prev->payload_size || l->payload_size > l->prev->payload_size)) {
					ndprint("Error, new len greater than the computed maximum len or buffer (maximum %u, new %u, layer %s). Not considering packet\n",
						l->prev && l->payload_start + l->payload_size, l->prev->payload_start + l->prev->payload_size, match_get_name(l->type));
					return 0;
				}

			}

		}



		// Check if the rule correspond to what we identified
		if (l->type != m->type)
			return 0;

		if (m->match_priv)
			result = match_eval(m, frame, start, len, l);


		start = l->payload_start;
	} else {
		next_layer = l;
		if (l->prev)
			start = l->prev->payload_start;
	}

	if (result == 0)
		return 0; // It doesn't match

	if (!n->a)
		return 1; // There is nothing else to match




	if (!n->b) // There is only one next node
		return node_match(frame, start, len, n->a, next_layer);


	// there is two node, let's see if we match one of them
	return node_match(frame, start, len, n->a, next_layer) && node_match(frame, start, len, n->b, next_layer);

}

int do_rules(void *frame, unsigned int start, unsigned int len, struct rule_list *rules, int first_layer) {

	

	frame += start;
	len -= start;
	
	struct rule_list *r = rules;
	if (r == NULL) {
		dprint("No rules given !\n");
		return 1;
	}


	// We need to discard the previous pool of layer before doing anything else
	layer_pool_discard();

	// Let's identify the layers as far as we can go
	struct layer *layers, *l;

	layers = layer_pool_get();
	l = layers;
	l->type = first_layer;
	while (l && l->type != match_undefined_id) { // If it's undefined, it means we can't assume anything about the rest of the packet
		l->next = layer_pool_get();
		l->next->prev = l;
		
		int new_start = 0, new_len = len;
		if (l->prev) {
			new_start = l->prev->payload_start;
			new_len = l->prev->payload_size;
		}

		// identify must populate payload_start and payload_size
		l->next->type = match_identify(l, frame, new_start, new_len);

		if (l->next->type == -1) {
			l->next = NULL;
		}
		
		l->infos = layer_info_pool_get(l);


		if (helper_need_help(l, frame, new_start, len)) // If it needs help, we don't process it
			return 1;
	
		// check the calculated size and adjust the max len of the packet
		// the initial size may be too long as some padding could have been introduced by the input

		if (l->prev && (l->payload_start + l->payload_size > l->prev->payload_start + l->prev->payload_size || l->payload_size > l->prev->payload_size)) {
			dprint("Error, new len greater than the computed maximum len or buffer (maximum %u, new %u, layer %s). Not considering packet\n",
				l->prev->payload_start + l->prev->payload_size, l->payload_start + l->payload_size, match_get_name(l->type));
			return 1;
		}



		l = l->next;
	}


	// Now, check each rule and see if it matches

	while (r) {

		if (r->node) {
			// If there is a conntrack_entry, it means one of the target added it's priv, so the packet needs to be processed
			r->result = node_match(frame, 0, len, r->node, layers); // Get the result to fully populate layers
			if (r->result)
				ndprint("Rule matched\n");
		}
		r = r->next;

	}

	struct conntrack_entry *ce = conntrack_get_entry(layers, frame);

	if (ce) { // We got a conntrack_entry, process the corresponding targets
		struct conntrack_target_priv *cp = ce->target_privs;
		while (cp) {
			r = rules;
			while (r) {
				struct target *t = r->target;
				while (t) {
					if (t == cp->t) {
						target_process(r->target, layers, frame, len, ce);
						t->matched_conntrack = 1; // Do no process this target again if it matched here
					}
					t = t->next;
				}
				r = r->next;
			}
			cp = cp->next;
		}
	}

	// Process the matched rules
	r = rules;
	while (r) {
		struct target *t = r->target;
		if (r->result) {
			while (t) {
				if (!t->matched_conntrack)
					target_process(t, layers, frame, len, ce);
				t = t->next;
			}
		}

		t = r->target;
		while (t) {
			t->matched_conntrack = 0;
			t = t->next;
		}
		r = r->next;
	}

	// reset matched_conntrack value

	
	return 1;
}



int node_destroy(struct rule_node *node, int sub) {

	static int done = 0;
	static struct rule_node **done_stack = NULL;

	if (!node)
		return 1;

	// We have to check for both nodes

	if (node->a && !node->a->match && !node->a->b) {
		int i = 0;
		for (i = 0; i < done; i++)
			if (done_stack[i] == node->a)
				node->a = NULL;

	}

	if (node->b && !node->b->match && !node->b->b) {
		int i = 0;
		for (i = 0; i < done; i++)
			if (done_stack[i] == node->b)
				node->b = NULL;

	}

	if (node->match)
		match_cleanup_module(node->match);
	else {
		done_stack = realloc(done_stack, sizeof(struct rule_node*) * (done + 1));
		done_stack[done] = node;
		done++;
	}
	

	if (node->a)
		node_destroy(node->a, 1);

	if (node->b)
		node_destroy(node->b, 1);
	
	free(node);

	if (!sub && done_stack) {
		free(done_stack);
		done_stack = NULL;
		done = 0;
	}
	
	return 1;

}

int list_destroy(struct rule_list *list) {

	if (!list)
		return 1;
	
	struct rule_list *tmp;
	
	do {
		tmp = list;
		list = list->next;
		if (tmp->node)
			node_destroy(tmp->node, 0);

		struct target* t = tmp->target;
		while (t) {
			struct target* next = t->next;
			target_close(t);
			target_cleanup_t(t);
			t = next;
		}
			
		free(tmp);

	} while (list);
	
	return 1;


}
