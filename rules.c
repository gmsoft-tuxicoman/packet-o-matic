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

	if (m) {

		// The current layer is not identified. Let's see if we can match with the current match type
		if (l->type == match_undefined_id) {
			unsigned int next_layer;
			l->type = m->match_type;
			next_layer = match_identify(l, frame, l->prev->payload_start, l->prev->payload_size);
			if (next_layer < 0) {
				// restore the original value
				l->type = match_undefined_id;
				return 0;
			} else {
				l->next = malloc(sizeof(struct layer)); // This is fred in do_rules
				bzero(l->next, sizeof(struct layer));
				l->next->type = next_layer;
			}

		}



		// Check if the rule correspond to what we identified
		if (l->type != m->match_type)
			return 0;

		if (m->match_priv)
			result = match_eval(m, frame, start, len, l);
	}

	if (result == 0)
		return 0; // It doesn't match

	if (!n->a)
		return 1; // There is nothing else to match


	if (!n->b) // There is only one next node
		return node_match(frame, l->payload_start, l->payload_size, n->a, l->next);


	if (n->andor) { // and
		return node_match(frame, l->payload_start, l->payload_size, n->a, l->next) && node_match(frame, l->payload_start, l->payload_size, n->b, l->next);

	} else { // or
		return node_match(frame, l->payload_start, l->payload_size, n->a, l->next) || node_match(frame, l->payload_start, l->payload_size, n->b, l->next);

	}
	
	// Never reached
	
	return 0;
	

}

int do_rules(void *frame, unsigned int start, unsigned int len, struct rule_list *rules, int first_layer) {

	

	frame += start;
	len -= start;
	
	struct rule_list *r = rules;
	if (r == NULL) {
		dprint("No rules given !\n");
		return 1;
	}

	// Let's identify the layers as far as we can go
	struct layer *layers, *l;

	layers = malloc(sizeof(struct layer));
	bzero(layers, sizeof(struct layer));
	l = layers;
	l->type = first_layer;
	while (l && l->type != match_undefined_id) { // If it's undefined, it means we can't assume anything about the rest of the packet
		l->next = malloc(sizeof(struct layer));
		bzero(l->next, sizeof(struct layer));
		l->next->prev = l;

		// identify must populate payload_start and payload_size
		if (l->prev)
			l->next->type = match_identify(l, frame, l->prev->payload_start, l->prev->payload_size);
		else
			l->next->type = match_identify(l, frame, 0, len);

		if (l->next->type == -1) {
			free(l->next);
			l->next = NULL;
		}



		if (helper_need_help(frame, l)) // If it needs help, we don't process it
			goto err;
	
		// check the calculated size and adjust the max len of the packet
		// the initial size may be too long as some padding could have been introduced by the input

		unsigned int new_len = l->payload_start + l->payload_size;
		if (new_len > len) {
			ndprint("Error, new len greater than the computed maximum len or buffer (maximum %u, new %u). Not considering packet\n", len, new_len);
			goto err;
		}

		len = new_len;


		l = l->next;
	}


	// Now, check each rule and see if it matches

	while (r) {

		// If there is a conntrack_entry, it means one of the target added it's priv, so the packet needs to be processed
		r->result = node_match(frame, 0, len, r->node, layers); // Get the result to fully populate layers
		if (r->result)
			ndprint("Rule matched\n");
		r = r->next;

	}

	struct conntrack_entry *ce = conntrack_get_entry(layers, frame);

	if (ce) { // We got a conntrack_entry, process the corresponding target
		struct conntrack_privs *cp = ce->privs;
		while (cp) {
			r = rules;
			while (r) {
				if (r->target == cp->priv_obj) {
					target_process(r->target, layers, frame, len, ce);
					r->result = 0; // Do no process this rule if it matches
				}
				r = r->next;
			}
			cp = cp->next;
		}
	}

	// Process the matched rules
	r = rules;
	while (r) {
		if (r->result && r->target)
				target_process(r->target, layers, frame, len, ce);
		r = r->next;
	}
err:
	l = layers;
	ndprint("layers : ");
	while (l) {
		ndprint("%u ", l->type);
		layers = l->next;
		free(l);
		l = layers;
	}
	ndprint("\n");


	
	return 1;
}



int node_destroy(struct rule_node *node, int sub) {

	static int done = 0;
	static struct rule_node **done_stack;

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
		match_cleanup(node->match);
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

	if (!sub)
		free(done_stack);
	
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
		if (tmp->target) {
			target_close(tmp->target);
			target_cleanup_t(tmp->target);
		}
			
		free(tmp);

	} while (list);
	
	return 1;


}
