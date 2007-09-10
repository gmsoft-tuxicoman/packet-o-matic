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


int dump_invalid_packet(struct frame *f) {

	struct layer *l = f->l;

	dprint("Invalid packet : frame len %u, bufflen %u > ", f->len, f->bufflen);

	while (l) {
		dprint("%s pstart %u, psize %u", match_get_name(l->type), l->payload_start, l->payload_size);
		l = l->next;
		if (l)
			dprint(" > ");

	}
	dprint("\n");

	return 0;
}

/**
 * Parameters :
 * - n : current node what we are evaluating
 * - l : current layer that we are currently looking at
 **/

int node_match(struct frame *f, struct rule_node *n, struct layer *l) {

	if (!l)
		return 0;

	int result = 1;

	struct layer *next_layer = l->next;

	if ((n->op & ~RULE_OP_NOT) == 0) {

		// The current layer is not identified. Let's see if we can match with the current match type
		if (l->type == match_undefined_id) {
			if (!l->prev) {
				ndprint("Error, first layer is undefined !\n");
				return 0;
			}
			unsigned int next_layer;
			l->type = n->layer;
			next_layer = match_identify(f, l, l->prev->payload_start, l->prev->payload_size);
			if (next_layer < 0) {
				// restore the original value
				l->type = match_undefined_id;
				return 0;
			} else {
				l->infos = layer_info_pool_get(l);
				l->next = layer_pool_get();
				l->next->type = next_layer;

				if (helper_need_help(f, l->prev->payload_start, l->prev->payload_size, l) == H_NEED_HELP) // If it needs help, we don't process it
					return 0;
			
				// check the calculated size and adjust the max len of the packet
				// the initial size may be too long as some padding could have been introduced by the input

				if (l->prev && (l->payload_start + l->payload_size > l->prev->payload_start + l->prev->payload_size || l->payload_size > l->prev->payload_size)) {
					dump_invalid_packet(f);
					return 0;
				}

			}

		}



		// Check if the rule correspond to what we identified
		if (l->type != n->layer) {
			// if there is a field to match, we apply the not operation on the field and not on the type
			if (n->match)
				return 0;
			return (n->op & RULE_OP_NOT);
		}

		if (n->match) {
			result = match_eval(n->match);
		}

	} else { // If there is an operation specified, it means this node is a 'or' or 'and' operation
		next_layer = l;
	}

	if (result == 0)
		return 0; // It doesn't match

	if (!n->a)
		return !(n->op & RULE_OP_NOT); // There is nothing else to match




	if (!n->b) { // There is only one next node
		if (n->op & RULE_OP_NOT)
			return !node_match(f, n->a, next_layer);
		else
			return node_match(f, n->a, next_layer);
	}


	// there is two node, let's see if we match one of them
	if (n->op & RULE_OP_OR)
		result = node_match(f, n->a, next_layer) || node_match(f, n->b, next_layer);
	else if (n->op & RULE_OP_AND)
		result = node_match(f, n->a, next_layer) && node_match(f, n->b, next_layer);
	else {
		dprint("Invalid rule specified for node with two subnodes.\n");
		return 0;
	}

	if (n->op & RULE_OP_NOT)
		return !result;

	return result;
}

int do_rules(struct frame *f, struct rule_list *rules) {

	
	
	struct rule_list *r = rules;
	if (r == NULL) {
		dprint("No rules given !\n");
		return 1;
	}


	// We need to discard the previous pool of layer before doing anything else
	layer_pool_discard();

	// Let's identify the layers as far as we can go
	struct layer *l;

	l = layer_pool_get();
	l->type = f->first_layer;


	f->l = l;
	f->ce = NULL;

	while (l && l->type != match_undefined_id) { // If it's undefined, it means we can't assume anything about the rest of the packet
		l->next = layer_pool_get();
		l->next->prev = l;
		
		int new_start = 0, new_len = f->len;
		if (l->prev) {
			new_start = l->prev->payload_start;
			new_len = l->prev->payload_size;
		}

		// identify must populate payload_start and payload_size
		l->next->type = match_identify(f, l, new_start, new_len);

		if (l->next->type == -1) {
			l->next = NULL;
		} else if (l->next->type != match_undefined_id)
			// Next layer is new. Need to discard current conntrack entry
			f->ce = NULL;
		
		l->infos = layer_info_pool_get(l);


		if (helper_need_help(f, new_start, new_len, l) == H_NEED_HELP) // If it needs help, we don't process it
			return 1;
	
		// check the calculated size and adjust the max len of the packet
		// the initial size may be too long as some padding could have been introduced by the input

		if (l->prev && (l->payload_start + l->payload_size > l->prev->payload_start + l->prev->payload_size || l->payload_size > l->prev->payload_size)) {
			dump_invalid_packet(f);
			return 1;
		}



		l = l->next;
	}


	// Now, check each rule and see if it matches

	while (r) {

		if (r->node) {
			// If there is a conntrack_entry, it means one of the target added it's priv, so the packet needs to be processed
			r->result = node_match(f, r->node, f->l); // Get the result to fully populate layers
			if (r->result)
				ndprint("Rule matched\n");
		}
		r = r->next;

	}

	if (f->ce || conntrack_get_entry(f) == C_OK) { // We got a conntrack_entry, process the corresponding targets
		struct conntrack_target_priv *cp = f->ce->target_privs;
		while (cp) {
			r = rules;
			while (r) {
				struct target *t = r->target;
				while (t) {
					if (t == cp->t) {
						target_process(r->target, f);
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
					target_process(t, f);
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

	if (node->a && node->a->op == 0 && !node->a->b) {
		int i = 0;
		for (i = 0; i < done; i++)
			if (done_stack[i] == node->a)
				node->a = NULL;

	}

	if (node->b && node->b->op == 0 && !node->b->b) {
		int i = 0;
		for (i = 0; i < done; i++)
			if (done_stack[i] == node->b)
				node->b = NULL;

	}

	if (node->op == 0) {
		done_stack = realloc(done_stack, sizeof(struct rule_node*) * (done + 1));
		done_stack[done] = node;
		done++;
	}
	

	if (node->a)
		node_destroy(node->a, 1);

	if (node->b)
		node_destroy(node->b, 1);

	if (node->match)
		match_cleanup_param(node->match);
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
