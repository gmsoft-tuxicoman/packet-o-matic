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


#include "rules.h"
#include "helper.h"

#include "ptype_uint64.h"

int match_undefined_id;


int rules_init() {

	match_undefined_id = match_register("undefined");

	return POM_OK;

}


int dump_invalid_packet(struct frame *f) {

	struct layer *l = f->l;

	pom_log(POM_LOG_DEBUG "Invalid packet : frame len %u, bufflen %u > ", f->len, f->bufflen);

	while (l) {
		pom_log(POM_LOG_DEBUG "%s pstart %u, psize %u", match_get_name(l->type), l->payload_start, l->payload_size);
		l = l->next;
		if (l)
			pom_log(POM_LOG_DEBUG " > ");

	}
	pom_log(POM_LOG_DEBUG "\r\n");

	return POM_OK;
}

/**
 * @param f Current frame
 * @param l Current layer that we are currently looking at
 * @param n Current node what we are evaluating
 * @param last Last node what we should evaluate
 * @return True or false. Set *l to the last matched layer.
 **/

int node_match(struct frame *f, struct layer **l, struct rule_node *n, struct rule_node *last) {

	if (n == last)
		return 1;


	while (n != last) {

		if (n->op == RULE_OP_TAIL) {
			n = n->a;
			continue;
		}

		if (!*l) {
			// There is no more layer to match
			return 0;
		}

		if (!n->b) { // Only one node is attached to this one
			// The current layer is not identified. Let's see if we can match with the current match type
			if ((*l)->type == match_undefined_id) {
				if (!(*l)->prev) {
					pom_log(POM_LOG_ERR "Error, first layer is undefined !\r\n");
					return 0;
				}
				unsigned int next_layer;
				(*l)->type = n->layer;
				if (layer_field_pool_get(*l) != POM_OK) {
					pom_log(POM_LOG_WARN "Could not get a field pool for this packet. Ignoring\r\n");
					return 0;
				}
				next_layer = match_identify(f, *l, (*l)->prev->payload_start, (*l)->prev->payload_size);
				if (next_layer < 0) {
					// restore the original value
					(*l)->type = match_undefined_id;
					return 0;
				} else {
					(*l)->next = layer_pool_get();
					(*l)->next->prev = *l;
					(*l)->next->type = next_layer;
	
					helper_lock(0);
					int res = helper_need_help(f, (*l)->prev->payload_start, (*l)->prev->payload_size, *l);
					helper_unlock();
					if (res == H_NEED_HELP)// If it needs help, we don't process it
						return 0;
				
					// check the calculated size and adjust the max len of the packet
					// the initial size may be too long as some padding could have been introduced by the input

					if ((*l)->prev && ((*l)->payload_start + (*l)->payload_size > (*l)->prev->payload_start + (*l)->prev->payload_size || (*l)->payload_size > (*l)->prev->payload_size)) {
						dump_invalid_packet(f);
						return 0;
					}

				}

			}
			if (n->layer == (*l)->type) { // See if the layer is what we are looking for
				if (n->match) {
					int result = match_eval(n->match, *l);
					if (n->op & RULE_OP_NOT)
						result = !result;
					if (!result)
						return 0;
				} else if (n->op & RULE_OP_NOT)
					return 0;


			} else if (!(n->op & RULE_OP_NOT)) {
				return 0;
			}
			n = n->a;
			*l = (*l)->next;

		} else { // Two nodes are attached to this one
			// find the last one that needs to be processed
			struct rule_node *new_last = NULL, *rn = n;
			int depth = 0;
			if (!n->last) {
				while (rn && rn != last) {
					if (rn->b) {
						depth++;
					} else if (rn->op == RULE_OP_TAIL) {
						depth--;
						if (depth == 0) {
							new_last = rn;
							n->last = new_last;
							break;
						}
					}
					rn = rn->a;
				}
			} else {
				new_last = n->last;
			}

			// let's see the result of the branch

			int result = 0;
			if (n->op & (RULE_OP_OR | RULE_OP_AND)) {
				int result_a, result_b;
				struct layer *layer_a = (*l), *layer_b = (*l);
				result_a = node_match(f, &layer_a, n->a, new_last);
				result_b = node_match(f, &layer_b, n->b, new_last);
				if (n->op & RULE_OP_OR)
					result = result_a || result_b;
				else
					result = result_a && result_b;
				if (!result) 
					return 0;
				if ((result_a && result_b) && (layer_a != layer_b)) { // we have to branch here because both side didn't match up to the same layer
					// last layer matched is different, branching
					if (result_a) 
						result_a = node_match(f, &layer_a, new_last, last);
					if (result_b)
						result_b = node_match(f, &layer_b, new_last, last);
					if (n->op & RULE_OP_OR)
						result = result_a || result_b;
					else
						result = result_a && result_b;
					return result;
				} else if (result_a) {
					*l = layer_a;
				} else if (result_b) {
					*l = layer_b;
				}

			} else {
				pom_log(POM_LOG_ERR "Error unexpected operation for rule node\r\n");
				return 0;
			}

			if (!result)
				return 0;
			n = new_last;
		}
	}
	return 1;
}

int do_rules(struct frame *f, struct rule_list *rules) {

	
	
	struct rule_list *r = rules;
	if (r == NULL) {
		return POM_OK;
	}


	// We need to discard the previous pool of layer before doing anything else
	layer_pool_discard();

	// Let's identify the layers as far as we can go
	struct layer *l;

	l = layer_pool_get();
	l->type = f->first_layer;
	if (layer_field_pool_get(l) != POM_OK) {
		pom_log(POM_LOG_WARN "Could not get a field pool for this packet. Ignoring\r\n");
		return POM_OK;
	}


	f->l = l;

	struct conntrack_entry *old_ce = f->ce;
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
		} else if (l->next->type != match_undefined_id) {
			// Next layer is new. Need to discard current conntrack entry
			f->ce = NULL;
			if (layer_field_pool_get(l->next) != POM_OK) {
				pom_log(POM_LOG_WARN "Could not get a field pool for this packet. Ignoring\r\n");
				return POM_OK;
			}
		}

		helper_lock(0);
		int res = helper_need_help(f, new_start, new_len, l);
		helper_unlock();
		if (res == H_NEED_HELP) // If it needs help, we don't process it
			return POM_OK;
	
		// check the calculated size and adjust the max len of the packet
		// the initial size may be too long as some padding could have been introduced by the input

		if (l->prev && (l->payload_start + l->payload_size > l->prev->payload_start + l->prev->payload_size || l->payload_size > l->prev->payload_size)) {
			dump_invalid_packet(f);
			return POM_OK;
		}



		l = l->next;
	}


	// Now, check each rule and see if it matches

	while (r) {
		r->result = 0;

		if (r->node && r->enabled) {
			// If there is a conntrack_entry, it means one of the target added it's priv, so the packet needs to be processed
			struct layer *start_l = f->l;
			r->result = node_match(f, &start_l, r->node, NULL); // Get the result to fully populate layers
			if (r->result) {
			//	pom_log(POM_LOG_TSHOOT "Rule matched\r\n");
				PTYPE_UINT64_INC(r->pkt_cnt, 1);
				PTYPE_UINT64_INC(r->byte_cnt, f->len);
			}
		}
		r = r->next;

	}

	expectation_process(f);

	if (conntrack_get_entry(f) == POM_OK && (old_ce == NULL || f->ce == old_ce)) { // We got a conntrack_entry, process the corresponding targets
		struct conntrack_target_priv *cp = f->ce->target_privs;
		while (cp) {
			// need buffer as the present cp can be deleted by target_process if an error occurs
			struct conntrack_target_priv *cp_next = cp->next;
			r = rules;
			while (r) {
				struct target *t = r->target;
				while (t) {
					if (t == cp->t && !t->matched) {
						target_process(t, f);
						t->matched = 1; // Do no process this target again if it matched here
					}
					t = t->next;
				}
				r = r->next;
			}
			cp = cp_next;
		}
	}

	// Process the matched rules
	r = rules;
	while (r) {
		struct target *t = r->target;
		if (r->result) {
			while (t) {
				if (!t->matched) {
					target_process(t, f);
					t->matched = 1;
				}
				t = t->next;
			}
		}
		r = r->next;

	}



	// reset matched_conntrack value
	
	r = rules;
	while (r) {
		struct target *t = r->target;
		while (t) {
			t->matched = 0;
			t = t->next;
		}
		r = r->next;
	}

	return POM_OK;
}



int node_destroy(struct rule_node *node, int sub) {

	static int done = 0;
	static struct rule_node **done_stack = NULL;

	if (!node)
		return POM_ERR;

	// We have to check for both nodes

	if (node->a) { // && node->a->op == RULE_OP_TAIL) {
		int i = 0;
		for (i = 0; i < done; i++)
			if (done_stack[i] == node->a)
				node->a = NULL;

	}

	if (node->b) { // && node->b->op == RULE_OP_TAIL) {
		int i = 0;
		for (i = 0; i < done; i++)
			if (done_stack[i] == node->b)
				node->b = NULL;

	}

	if (node->op == RULE_OP_TAIL) {
		done_stack = realloc(done_stack, sizeof(struct rule_node*) * (done + 1));
		done_stack[done] = node;
		done++;
	} else if ((node->op & ~RULE_OP_NOT) != RULE_OP_AND && (node->op & ~RULE_OP_NOT) != RULE_OP_OR)
		match_refcount_dec(node->layer);
	

	if (node->a)
		node_destroy(node->a, 1);

	if (node->b)
		node_destroy(node->b, 1);

	if (node->match)
		match_cleanup_field(node->match);
	free(node);

	if (!sub && done_stack) {
		free(done_stack);
		done_stack = NULL;
		done = 0;
	}
	
	return POM_OK;

}

int list_destroy(struct rule_list *list) {

	if (!list)
		return POM_ERR;
	
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
			target_cleanup_module(t);
			t = next;
		}
		ptype_cleanup(tmp->pkt_cnt);
		ptype_cleanup(tmp->byte_cnt);
		free(tmp);

	} while (list);
	
	return POM_OK;


}
