/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pthread.h>

#include "ptype_uint64.h"

static int match_undefined_id;


int rules_init() {

	match_undefined_id = match_register("undefined");

	uid_init();

	return POM_OK;

}

int dump_invalid_packet(struct frame *f) {

	struct layer *l = f->l;
	char buff[2048];
	memset(buff, 0, sizeof(buff));
	snprintf(buff, sizeof(buff), "Invalid packet : frame len %u, bufflen %u > ", f->len, f->bufflen);

	while (l) {
		snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff) - 1, "%s pstart %u, psize %u", match_get_name(l->type), l->payload_start, l->payload_size);
		l = l->next;
		if (l)
			snprintf(buff + strlen(buff), sizeof(buff) - strlen(buff) - 1, " > ");

	}
	pom_log(POM_LOG_DEBUG "%s", buff);

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
					pom_log(POM_LOG_ERR "Error, first layer is undefined !");
					return 0;
				}
				unsigned int next_layer;
				(*l)->type = n->layer;
				if (layer_field_pool_get(*l) != POM_OK) {
					pom_log(POM_LOG_WARN "Could not get a field pool for this packet. Ignoring");
					return 0;
				}
				next_layer = match_identify(f, *l, (*l)->prev->payload_start, (*l)->prev->payload_size);
				if (next_layer == POM_ERR) {
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
				pom_log(POM_LOG_ERR "Error unexpected operation for rule node");
				return 0;
			}

			if (!result)
				return 0;
			n = new_last;
		}
	}
	return 1;
}

int do_rules(struct frame *f, struct rule_list *rules, pthread_rwlock_t *rule_lock) {


	// We need to discard the previous pool of layer before doing anything else
	layer_pool_discard();

	// Let's identify the layers as far as we can go
	struct layer *l;

	l = layer_pool_get();
	l->type = f->first_layer;
	if (layer_field_pool_get(l) != POM_OK) {
		pom_log(POM_LOG_WARN "Could not get a field pool for this packet. Ignoring");
		return POM_OK;
	}


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

		if (l->next->type == POM_ERR) {
			l->next = NULL;
		} else if (l->next->type != match_undefined_id) {
			// Next layer is new. Need to discard current conntrack entry
			f->ce = NULL;
			if (layer_field_pool_get(l->next) != POM_OK) {
				pom_log(POM_LOG_WARN "Could not get a field pool for this packet. Ignoring");
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


	if (rule_lock && pthread_rwlock_rdlock(rule_lock)) {
		pom_log(POM_LOG_ERR "Unable to lock the given rules");
		return POM_ERR;
	}

	struct rule_list *r = rules;
	if (r == NULL) {
		pthread_rwlock_unlock(rule_lock);
		return POM_OK;
	}

	while (r) {
		r->result = 0;

		if (r->node && r->enabled) {
			// If there is a conntrack_entry, it means one of the target added it's priv, so the packet needs to be processed
			struct layer *start_l = f->l;
			r->result = node_match(f, &start_l, r->node, NULL); // Get the result to fully populate layers
			if (r->result) {
			//	pom_log(POM_LOG_TSHOOT "Rule matched");
				PTYPE_UINT64_INC(r->pkt_cnt, 1);
				PTYPE_UINT64_INC(r->byte_cnt, f->len);
			}
		}
		r = r->next;

	}

	expectation_process(f);

	if (conntrack_get_entry(f) == POM_OK) { // We got a conntrack_entry, process the corresponding targets
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

	if (rule_lock && pthread_rwlock_unlock(rule_lock)) {
		pom_log(POM_LOG_ERR "Unable to unlock the given rule_lock");
		return POM_ERR;
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
			target_lock_instance(t, 1);
			struct target* next = t->next;
			target_close(t);
			target_cleanup_module(t);
			t = next;
		}
		ptype_cleanup(tmp->pkt_cnt);
		ptype_cleanup(tmp->byte_cnt);

		if (tmp->description)
			free(tmp->description);

		free(tmp);

	} while (list);
	
	return POM_OK;


}

int rule_print_flat(struct rule_node *n, struct rule_node *last, char *buffer, size_t buff_len) {

	if (n == last)
		return 0;


	int display_parenthesis = 0;

	if (last != NULL && n->a && n->a->op != RULE_OP_TAIL)
		display_parenthesis = 1;


	if (n->op & RULE_OP_NOT && n->b) {
		strncat(buffer, "!", buff_len);
		buff_len--;
		if (!buff_len)
			return POM_ERR;
		display_parenthesis = 1;
	}



	if (display_parenthesis) {
		strncat(buffer, "(", buff_len);
		buff_len--;
		if (!buff_len)
			return POM_ERR;
	}

	while (n != last) {

		if (!n->b) {
			if (n->op != RULE_OP_TAIL) {
				if (n->op & RULE_OP_NOT) {
					strncat(buffer, "!", buff_len);
					buff_len--;
					if (!buff_len)
						return POM_ERR;
				}
				char *match_name = match_get_name(n->layer);
				int len = strlen(match_name);
				if (buff_len < len)
					return POM_ERR;
				strncat(buffer, match_name, buff_len);
				buff_len -= len;
				if (n->match) {

					strncat(buffer, ".", buff_len);
					buff_len--;
					if (!buff_len)
						return POM_ERR;

					struct match_field_reg *field = match_get_field(n->layer, n->match->id);

					if (buff_len < strlen(field->name))
						return POM_ERR;
					strncat(buffer, field->name, buff_len);
					buff_len -= strlen(field->name);

					strncat(buffer, " ", buff_len);
					buff_len--;
					if (!buff_len)
						return POM_ERR;

					char *op = ptype_get_op_sign(n->match->op);
					if (buff_len < strlen(op))
						return POM_ERR;
					strncat(buffer, op, buff_len);
					buff_len -= strlen(op);

					strncat(buffer, " ", buff_len);
					buff_len--;
					if (!buff_len)
						return POM_ERR;

					char val_buff[255];
					ptype_print_val(n->match->value, val_buff, sizeof(val_buff) - 1);
					if (buff_len < strlen(val_buff))
						return POM_ERR;
					strncat(buffer, val_buff, buff_len);
					buff_len -= strlen(val_buff);

				}
			}
			n = n->a;

		} else {
			// fin the last one that needs to be processed
			struct rule_node *new_last = NULL, *rn = n;
			int depth = 0;
			while (rn && rn != last) {
				if (rn->b) {
					depth++;
				} else if (rn->op == RULE_OP_TAIL) {
					depth--;
					if (depth == 0) {
						new_last = rn;
						break;
					}
				}
				rn = rn->a;
			}

			rule_print_flat(n->a, new_last, buffer, buff_len);
			if (n->op & RULE_OP_OR) {
				char *or = " or ";
				strncat(buffer, or, buff_len);
				buff_len -= strlen(or);
			} else if (n->op & RULE_OP_AND) {
				char *or = " and ";
				strncat(buffer, or, buff_len);
				buff_len -= strlen(or);
			}
			rule_print_flat(n->b, new_last, buffer, buff_len);

			n = new_last;
		}
		if (n && n->op != RULE_OP_TAIL) {
			char *sep = " | ";
			strncat(buffer, sep, buff_len);
			buff_len -= strlen(sep);
		}
	}
	if (display_parenthesis) {
		strncat(buffer, ")", buff_len);
		buff_len--;
		if (!buff_len)
			return POM_ERR;
	}
	return POM_OK;
}


static struct rule_node *rule_parse_block(char *expr, char *errbuff, int errlen) {

	char *words[3]; 
	int wordcount = 0;

	char *str, *token, *saveptr = NULL;

	for (str = expr; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (token == NULL)
			break;
		
		// there should not be more than 3 words
		if (wordcount >= 3) {
			snprintf(errbuff, errlen, "Could not parse \"%s\"", expr);
			return NULL;
		}

		words[wordcount] = token;
		wordcount++;
		
	}

	if (wordcount == 2) {
		snprintf(errbuff, errlen, "Could not parse \"%s\"", expr);
		return NULL;
	}

	if (wordcount == 1) {
		int layer = match_get_type(words[0]);
		if (layer == POM_ERR) 
			layer = match_register(words[0]);
		if (layer == POM_ERR) {
			snprintf(errbuff, errlen, "Unknown match \"%s\"", words[0]);
			return NULL;
		}
		match_refcount_inc(layer);
		struct rule_node *rn = malloc(sizeof(struct rule_node));
		memset(rn, 0, sizeof(struct rule_node));

		rn->layer = layer;
		return rn;
	}
	

	// wordcount is supposed to be 3 now
	char *field = strchr(words[0], '.');
	if (!field) {
		snprintf(errbuff, errlen, "Expression \"%s\" doesn't not contain a field specifier", words[0]);
		return NULL;
	}

	*field = 0;
	field++;
	int layer = match_get_type(words[0]);
	if (layer == POM_ERR)
		layer = match_register(words[0]);
	if (layer == POM_ERR) {
		snprintf(errbuff, errlen, "Unknown match \"%s\"", words[0]);
		return NULL;
	}
	
	struct match_field *param;
	param = match_alloc_field(layer, field);
	if (param == NULL) {
		snprintf(errbuff, errlen, "Unknown field \"%s\" for match \"%s\"", field, words[0]);
		return NULL;
	}

	param->op = ptype_get_op(param->value, words[1]);
	if (param->op == POM_ERR) {
		snprintf(errbuff, errlen, "Unknown or unsuported operation \"%s\" for field \"%s\" and match \"%s\"", words[1], field, words[0]);
		match_cleanup_field(param);
		return NULL;
	}

	if (ptype_parse_val(param->value, words[2]) == POM_ERR) {
		snprintf(errbuff, errlen, "Unable to parse \"%s\" for field \"%s\" and match \"%s\"", words[2], field, words[0]);
		match_cleanup_field(param);
		return NULL;
	}

	struct rule_node *rn = malloc(sizeof(struct rule_node));
	memset(rn, 0, sizeof(struct rule_node));
	rn->layer = layer;
	rn->match = param;
	match_refcount_inc(layer);
	return rn;

}

static int rule_parse_branch(char *expr, struct rule_node **start, struct rule_node **end, char *errbuff, int errlen) {

	int stack_size = 0;
	int i, len;
	len = strlen(expr);
	
	int found = 0; // what operation was found
	int found_len = 0; // lenght of the string matched

	// let's see if there is a branch
	for (i = 0; i < len - 2; i++) {
		if (stack_size == 0 && expr[i] == 'o' && expr[i + 1] == 'r') {
			found = RULE_OP_OR;
			found_len = 2;
		}
		if (stack_size == 0 && expr[i] == 'a' && expr[i + 1] == 'n' && expr[i + 2] == 'd') {
			found = RULE_OP_AND;
			found_len = 3;
		}

		if (found) {
			if (i < 1 || i > len - found_len) {
				found = 0;
				continue;
			}
			if (expr[i - 1] != ')' && expr[i - 1] != ' ') {
				found = 0;
				continue;
			}

			if (expr[i + found_len] != ' ' && expr[i + found_len] != '(' && expr[i + found_len] != '!') {
				found = 0;
				continue;
			}

			expr[i] = 0;

			struct rule_node *my_start = malloc(sizeof(struct rule_node));
			memset(my_start, 0, sizeof(struct rule_node));

			struct rule_node *my_end = malloc(sizeof(struct rule_node));
			memset(my_end, 0, sizeof(struct rule_node));
			my_start->op = found;
			my_end->op = RULE_OP_TAIL;

			*start = my_start;
			*end = my_end;

			struct rule_node *the_end = NULL;
			if (rule_parse(expr, &my_start->a, &the_end, errbuff, errlen) == POM_ERR)
				return POM_ERR;
			if (!the_end)
				return POM_ERR;

			the_end->a = my_end;
			if (rule_parse(expr + i + found_len, &my_start->b, &the_end, errbuff, errlen) == POM_ERR)
				return POM_ERR;
			the_end->a = my_end;

			return POM_OK;
		}
				

		if (expr[i] == '(') {
			stack_size++;
			continue;
		}

		if (expr[i] == ')') {
			stack_size--;
			if (stack_size < 0) {
				snprintf(errbuff, errlen, "Unmatched )\r\n");
				return POM_ERR;
			}
		}


	}



	int inv = 0; // should this match be inverted
	// first, trim this expr
	while(*expr == ' ')
		expr++;
	while (strlen(expr) > 0 && expr[strlen(expr) - 1] == ' ')
		expr[strlen(expr) - 1] = 0;

	if (expr[0] == '!') {
		inv = 1;
		expr++;
		while(*expr == ' ')
			expr++;
	}
	if (expr[0] == '(' && strlen(expr) > 0 && expr[strlen(expr) - 1] == ')') { // parenthesis at begining and end of block
		expr++;
		expr[strlen(expr) - 1] = 0;
		if (rule_parse(expr, start, end, errbuff, errlen) == POM_ERR)
			return POM_ERR;

		if (inv) {
			if ((*start)->b){
				snprintf(errbuff, errlen,"Unexpected \"!\"\r\n");
				return POM_ERR;
			}
			(*start)->op |= RULE_OP_NOT;
		}
		return POM_OK;
	}

	*start = rule_parse_block(expr, errbuff, errlen);
	if (!*start)
		return POM_ERR;
	*end = *start;

	if (inv) {
		if ((*start)->b) {
			snprintf(errbuff, errlen, "Cannot use '!' with or/and operation\r\n");
			return POM_ERR;
		} else
			(*start)->op |= RULE_OP_NOT;
	}
	return POM_OK;
}


int rule_parse(char *expr, struct rule_node **start, struct rule_node **end, char *errbuff, int errlen) {

	int pstart = 0;
	int stack_size = 0;
	int i, len;

	struct rule_node *my_start, **my_start_addr;
	my_start_addr = &my_start;

	*start = NULL;

	len = strlen(expr);
	for (i = 0; i < len; i++) {
		if (stack_size == 0 && expr[i] == '|') {
			expr[i] = 0;
			if (rule_parse_branch(expr + pstart, my_start_addr, end, errbuff, errlen) == POM_ERR)
				return POM_ERR;
			if (!*start)
				*start = *my_start_addr;
			my_start_addr = &(*end)->a;

			pstart = i + 1;
		}
		if (expr[i] == '(') {
			stack_size++;
			continue;
		}
		
		if (expr[i] == ')') {
			stack_size--;
			if (stack_size < 0) {
				snprintf(errbuff, errlen, "Unmatched )\r\n");
				return POM_ERR;
			}
		}
	}

	if (stack_size > 0) {
		snprintf(errbuff, errlen, "Unmatched (\r\n");
		return POM_ERR;
	}

	// parse the last block
	if (rule_parse_branch(expr + pstart, my_start_addr, end, errbuff, errlen) == POM_ERR)
		return POM_ERR;
	if (!*start)
		*start = *my_start_addr;


	return POM_OK;
}
