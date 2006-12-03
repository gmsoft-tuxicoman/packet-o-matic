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


#include "rules.h"
#include "helper.h"

int match_undefined_id;


int rules_init() {

	match_undefined_id = match_register("undefined");

	return 1;

}

int do_rules(void *frame, unsigned int start, unsigned int len, struct rule_list *rules, int first_layer) {

	
	struct rule_list *r = rules;

	frame += start;
	len -= start;
	
	if (r == NULL) {
		dprint("No rules given !\n");
		return 1;
	}

	do {
		if (r->node && r->node->match && r->node->match->match_type == first_layer)
			if (node_match(frame, 0, len, r->node))
				if (r->target)
					target_process(r->target, r->node, frame, len);

		r = r->next;
	}  while (r != NULL);

	
	return 1;
}

inline int node_match(void *frame, unsigned int start, unsigned int len, struct rule_node *node) {

	struct match *m = node->match;

	if (!m) {
		dprint("no match defined in rule\n");
		return 1;
	}

	int result;

	result = match_eval(m, frame, start, len);
	
	unsigned int new_len;
	new_len = m->next_start + m->next_size;
	if (new_len > len) {
		ndprint("Error, new len greater than the computed maximum len or buffer (maximum %u, new %u)\n", len, new_len);
		return 0;
	}

	len = new_len;

	// Does this layer needs a little help ?
	if (helper_need_help(frame, m))
		return 0;
	
	if (result == 0)
		return 0;

	if (!node->a)
		return 1;

	if (!node->b) {
		node->a->match->prev = m;

		if (m->next_layer == match_undefined_id)
			m->next_layer = node->a->match->match_type;
		if (node->a->match && node->a->match->match_type == m->next_layer && node_match(frame, m->next_start, len, node->a)) {
			m->next = node->a->match;
			return 1;
		}
		return 0;
	} else if (node->andor) { // AND = 1

		node->a->match->prev = m;
		node->b->match->prev = m;

		if (node->b->match && ((m->next_layer == match_undefined_id) || (node->a->match->match_type == m->next_layer)) && node->b->match->match_type == m->next_layer) {
			int aresult, bresult;
			aresult = node_match(frame, m->next_start, len, node->a);
			if (aresult == 0)
				return 0;
			bresult = node_match(frame, m->next_start, len, node->b);
			if (bresult == 0)
				return 0;
			// If both match, it means both have the same next_layer and thus next_start
			// We can thus choose only the first one
			m->next = node->a->match;
			if (m->next_layer == match_undefined_id)
				m->next_layer = node->a->match->match_type;
			return 1;
		} else
			return 0;
	} else { // OR = 0
		int aresult, bresult;
		node->a->match->prev = m;
		node->b->match->prev = m;

		if (node->a->match && ((m->next_layer == match_undefined_id) || (node->a->match->match_type == m->next_layer))) {
			aresult = node_match(frame, m->next_start, len, node->a);
			m->next = node->a->match;
			m->next_layer = node->a->match->match_type;
		} else
			aresult = 0;
	
		if (node->b->match && ((m->next_layer == match_undefined_id) || (node->b->match->match_type == m->next_layer))) {
			bresult = node_match(frame, m->next_start, len, node->b);
			m->next = node->b->match;
			m->next_layer = node->b->match->match_type;
		} else
			bresult = 0;

		return (aresult || bresult);
			
	}

	// Never reached
	return 0;
	

}

int node_destroy(struct rule_node *node) {

	if (!node)
		return 1;

	if (node->a)
		node_destroy(node->a);
	
	if (node->b)
		node_destroy(node->b);


	if (node->match)
		match_cleanup(node->match);

	free(node);

	
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
			node_destroy(tmp->node);
		if (tmp->target) {
			target_close(tmp->target);
			target_cleanup_t(tmp->target);
		}
			
		free(tmp);

	} while (list);
	
	return 1;


}
