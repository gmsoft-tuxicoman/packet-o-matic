
#include "rules.h"


int match_undefined_id;



int do_rules(void *frame, unsigned int start, unsigned int len, struct rule_list *rules) {

	
	struct rule_list *r = rules;
	
	// OPTIMIZE THIS
	match_undefined_id = match_get_type("undefined");
	
	if (r == NULL) {
		printf("No rules given !\n");
		return 1;
	}
	do {
		if (r->node)
			if (node_match(frame, start, len, r->node))
				if (r->target)
					target_process(r->target, r->node, frame, len);

		r = r->next;
	}  while (r != NULL);

	
	return 1;
}

int node_match(void *frame, unsigned int start, unsigned int len, struct rule_node *node) {

	struct match *m = node->match;


	int result;
	
	result = match_eval(m, frame, start, len);
	


	if (result == 0)
		return 0;

	if (!node->a)
		return 1;


	if (!node->b) {
		if (node->a->match && (m->next_layer == match_undefined_id || node->a->match->match_type == m->next_layer) && node_match(frame, m->next_start, len, node->a)) {
			m->next = node->a->match;
			node->a->match->prev = m;
			return 1;
		}
		return 0;
	} else if (node->andor) { // AND = 1

		if (node->b->match && ((m->next_layer == match_undefined_id) || (node->a->match->match_type == m->next_layer)) && node->b->match->match_type == m->next_layer) {
			int aresult, bresult;
			aresult = node_match(frame, m->next_start, len, node->a);
			if (aresult == 0)
				return 0;
			bresult = node_match(frame, m->next_start, len, node->b);
			if (bresult == 0)
				return 0;
			node->a->match->prev = m;
			node->b->match->prev = m;
			// If both match, it means both have the same next_layer and thus next_start
			// We can thus choose only the first one
			m->next = node->a->match;
			return 1;
		} else
			return 0;
	} else { // OR = 0
		int aresult, bresult;
		if (node->a->match && ((m->next_layer == match_undefined_id) || (node->a->match->match_type == m->next_layer))) {
			aresult = node_match(frame, m->next_start, len, node->a);
			m->next = node->a->match;
			node->a->match->prev = m;
		} else
			aresult = 0;
	
		if (node->b->match && ((m->next_layer == match_undefined_id) || (node->b->match->match_type == m->next_layer))) {
			bresult = node_match(frame, m->next_start, len, node->b);
			m->next = node->b->match;
			node->b->match->prev = m;
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
	
	struct rule_node *tmp;
	
	do {
		tmp = node;
		if (tmp->b)
			node_destroy(tmp->b);
		node = node->a;
		if (tmp->match) {
			if (tmp->match->match_priv)
				free(tmp->match->match_priv);
			free(tmp->match);
		}
		free(tmp);

	} while (node);
	
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
		if (tmp->target)
			target_close(tmp->target);
			
		free(tmp);

	} while (list);
	
	return 1;


}