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

#include "common.h"
#include "expectation.h"
#include "match.h"
#include "target.h"
#include "conntrack.h"
#include "timers.h"

static struct expectation_list *expt_head;

static int match_undefined_id;

/**
 * @ingroup expectation_core
 * @return POM_OK on success, POM_ERR on failure.
 **/
int expectation_init() {

	match_undefined_id = match_register("undefined");

	return POM_OK;

}

/**
 * @ingroup expectation_api
 * @param t Target which creates the expectation
 * @param ce Conntrack entry creating this expectation
 * @param i Input from which we expect the packets from
 **/

struct expectation_list *expectation_alloc(struct target *t, struct conntrack_entry *ce, struct input *i, int direction) {

	struct expectation_list *lst = malloc(sizeof(struct expectation_list));
	memset(lst, 0, sizeof(struct expectation_list));

	lst->parent_ce = ce;
	lst->t = t;
	lst->flags = direction;
	lst->expiry = timer_alloc(lst, i, expectation_do_timer);

	
	return lst;

}

/**
 * @ingroup expectation_api
 * @param lst Expectation list to add a layer to
 * @param match_type Type of layer to add
 **/

struct expectation_node *expectation_add_layer(struct expectation_list *expt, int match_type) {


	struct expectation_node *last_node = expt->n;
	while (last_node && last_node->next)
		last_node = last_node->next;
	
	struct expectation_node *n = malloc(sizeof(struct expectation_node));
	memset(n, 0, sizeof(struct expectation_node));

	n->layer = match_type;

	match_refcount_inc(match_type);

	if (last_node)
		last_node->next = n;
	else
		expt->n = n;

	int i;
	for (i = 0; i < MAX_LAYER_FIELDS; i++) {
		struct expectation_field *tmp = n->fields;
		int processed = 0;
		while (tmp) {
			if (tmp->field_id == i) {
				processed = 1;
				break;
			}
			tmp = tmp->next;
		}
		if (processed)
			continue;

		int field_id = match_get_expectation(match_type, i, EXPT_DIR_FWD);
		int field_id_rev = match_get_expectation(match_type, i, EXPT_DIR_REV);
		
		if (field_id != POM_ERR) { // Add the forward direction if needed
			if (field_id != i) {
				pom_log(POM_LOG_WARN "Warning, match_get_expectation forward direction didn't returned itself !");
				continue;
			}	
			
			struct expectation_field *fld = malloc(sizeof(struct expectation_field));
			memset(fld, 0, sizeof(struct expectation_field));
			fld->op = EXPT_OP_IGNORE;
		
			struct match_field_reg *fld_reg = match_get_field(match_type, i);
			fld->name = fld_reg->name;
			fld->field_id = field_id;

			fld->next = n->fields;
			n->fields = fld;

			if (field_id_rev != POM_ERR) { // Add reverse direction
				if (match_get_expectation(match_type, field_id_rev, EXPT_DIR_REV) != field_id) {
					pom_log(POM_LOG_WARN "Warning, match_get_expectation didn't returned the expected id for reverse-reverse direction");
					continue;
				}

				struct expectation_field *fld_rev = malloc(sizeof(struct expectation_field));
				memset(fld_rev, 0, sizeof(struct expectation_field));
				fld_rev->op = EXPT_OP_IGNORE;
			
				fld_reg = match_get_field(match_type, field_id_rev);
				fld_rev->name = fld_reg->name;
				fld_rev->field_id = field_id_rev;

				fld_rev->next = n->fields;
				n->fields = fld_rev;

				fld->rev = fld_rev;
				fld_rev->rev = fld;

			}

		}

	}

	return n;

}

/**
 * @ingroup expectation_api
 * @param n Layer which contains the field to set the value to
 * @param fld_name Field name to set the value to
 * @param fld_value Value to set
 * @param op Operation to perform to match this field
 **/

int expectation_layer_set_field(struct expectation_node *n, char *fld_name, char *fld_value, int op) {

	struct expectation_field *fld = n->fields;
	while (fld) {
		if (!strcmp(fld->name, fld_name))
			break;
		fld = fld->next;
	}

	if (!fld) {
		pom_log(POM_LOG_WARN "Field %s not found in given expectation");
		return POM_ERR;
	}

	fld->op = op;

	if (op == EXPT_OP_IGNORE) {
		if (fld->value) {
			ptype_cleanup(fld->value);
			fld->value = NULL;
		}
	} else {
		if (!fld->value) {
			struct match_field_reg *m_fld_reg = match_get_field(n->layer, fld->field_id);
			fld->value = ptype_alloc_from(m_fld_reg->type);
			if (!fld->value) {
				pom_log(POM_LOG_WARN "Unable to allocate value for field %s");
				return POM_ERR;
			}
		}
		return ptype_parse_val(fld->value, fld_value);
	}

	return POM_OK;

}

/**
 * @ingroup expectation_api
 * @param f Frame to use to generate the expectation
 * @param t Target which creates the expectation
 * @param ce Conntrack entry creating this expectation
 * @param direction Directions that needs to be matched
 * @return An expectation_list that will match the current packet
 **/
struct expectation_list *expectation_alloc_from(struct frame *f, struct target *t, struct conntrack_entry *ce, int direction) {

	struct layer *l = f->l;

	if (!l)
		return NULL;

	struct expectation_list *lst = expectation_alloc(t, ce, f->input, direction);

	if (!lst)
		return NULL;



	while (l && l->type != match_undefined_id) {
		struct expectation_node *n = expectation_add_layer(lst, l->type);
		if (!n)
			continue;
		struct expectation_field *fld = n->fields;
		while (fld) {
			if (l->fields[fld->field_id]) {
				fld->op = PTYPE_OP_EQ;
				fld->value = ptype_alloc_from(l->fields[fld->field_id]);
			}
			fld = fld->next;
		}

		l = l->next;

	}
	
	return lst;
}

int expectation_set_target_priv(struct expectation_list *l, void *target_priv, int (*cleanup_handler) (struct target *t, struct conntrack_entry *ce, void *priv)) {

	if (l->target_priv) {
		pom_log(POM_LOG_WARN "Warning, target priv already set for this expectation");
		return POM_ERR;
	}
	l->target_priv = target_priv;
	l->target_priv_cleanup_handler = cleanup_handler;

	return POM_OK;

}

int expectation_add(struct expectation_list *l, unsigned int expiry) {

	if (l->next || l->prev || l == expt_head) {
		pom_log(POM_LOG_WARN "Warning, expectation already added");
		return POM_ERR;
	}
	
	if (expt_head)
		expt_head->prev = l;
	l->next = expt_head;
	expt_head = l;

	timer_queue(l->expiry, expiry);

	return POM_OK;
}


int expectation_cleanup_ce(struct target *t, struct conntrack_entry *ce) {

	// Expectation list should be very small so we can just browse it
	struct expectation_list *tmp = expt_head;
	while (tmp) {
		struct expectation_list *next = tmp->next;
		if (tmp->t == t && tmp->parent_ce == ce) {
			expectation_cleanup(tmp);
			// Do not break, there could be more than one per target/conntrack entry
		}
		tmp = next;
	}

	return POM_OK;

}

int expectation_cleanup(struct expectation_list *l) {

	if (l->prev)
		l->prev->next = l->next;
	else
		expt_head = l->next;

	if (l->next)
		l->next->prev = l->prev;

	timer_cleanup(l->expiry);

	struct expectation_node *n = l->n;
	while (n) {
		match_refcount_dec(n->layer);
		struct expectation_field *fld = n->fields;
		while (fld) {
			n->fields = fld->next;
			ptype_cleanup(fld->value);
			free(fld);
			fld = n->fields;
		}

		struct expectation_node *tmp = n;
		n = n->next;
		free(tmp);
	}

	free(l);

	return POM_OK;

}

int expectation_cleanup_all() {

	while (expt_head) {
		if (expt_head->t && expt_head->target_priv && expt_head->target_priv_cleanup_handler)
			(*expt_head->target_priv_cleanup_handler) (expt_head->t, NULL, expt_head->target_priv);
		expectation_cleanup(expt_head);
	}
	return POM_OK;

}

int expectation_do_timer(void *priv) {

	struct expectation_list *l = priv;

	if (l->t && l->target_priv && l->target_priv_cleanup_handler)
		(*l->target_priv_cleanup_handler) (l->t, NULL, l->target_priv);

	expectation_cleanup(l);

	return POM_OK;

}


int expectation_process(struct frame *f) {


	struct expectation_list *expt = expt_head;

	while (expt) {

		struct layer *l;

		struct expectation_node *n = expt->n;

		int process = 1;

		// Check if forward direction match
		if (expt->flags & EXPT_DIR_FWD) {
			
			// Find the first layer that matches the expectation
			for (l = f->l; l && n->layer != l->type; l = l->next);

			while (n) {

				if (!l || n->layer != l->type) {
					process = 0;
					break;
				}

				struct expectation_field *fld = n->fields;
				while (fld) {
					if (fld->op == EXPT_OP_IGNORE) {
						fld = fld->next;
						continue;
					}

					if (!ptype_compare_val(fld->op, l->fields[fld->field_id], fld->value)) {
						process = 0;
						break;
					}
					fld = fld->next;

				}
				if (!process)
					break;

				l = l->next;
				n = n->next;
			}
			if (process)
				pom_log(POM_LOG_TSHOOT "Matched expectation in forward direction");
		}

		// Check if reverse direction match only if forward didn't match or wasn't evaluated
		if (expt->flags & EXPT_DIR_REV && (!(expt->flags & EXPT_DIR_FWD) || ((expt->flags & EXPT_DIR_FWD) && !process))) {
			process = 1;

			// Find the first layer that matches the expectation
			for (l = f->l; l && n->layer != l->type; l = l->next);

			while (n) {

				if (!l || n->layer != l->type) {
					process = 0;
					break;
				}

				struct expectation_field *fld = n->fields;
				while (fld) {
					if (!fld->rev) {
						fld = fld->next;
						continue;
					}
					if (fld->rev->op == EXPT_OP_IGNORE) {
						fld = fld->next;
						continue;
					}

					if (!ptype_compare_val(fld->rev->op, l->fields[fld->field_id], fld->rev->value)) {
						process = 0;
						break;
					}
					fld = fld->next;

				}
				if (!process)
					break;

				l = l->next;
				n = n->next;
			}
			if (process)
				pom_log(POM_LOG_TSHOOT "Matched expectation in reverse direction");
		}


		if (process) {
			if (!f->ce) // Make sure no connection already exists for that expectation
				conntrack_get_entry(f);
			
			if (f->ce) {
				if (expt->target_priv) {
					struct conntrack_target_priv *tp = f->ce->target_privs;
					int found_dup = 0;
					while (tp) {
						if (expt->t == tp->t) {
							
							if (expt->parent_ce == f->ce) {
								pom_log(POM_LOG_DEBUG "Expectation matched parent connection, ignoring.");
								if (expt->t && expt->target_priv && expt->target_priv_cleanup_handler)
									(*expt->target_priv_cleanup_handler) (expt->t, NULL, expt->target_priv);
								expectation_cleanup(expt);
								return POM_OK;
							}

							pom_log(POM_LOG_DEBUG "Expected connection already has a target_priv from the same target. Ignoring");

							if (expt->t && expt->target_priv && expt->target_priv_cleanup_handler)
								(*expt->target_priv_cleanup_handler) (expt->t, NULL, expt->target_priv);
							expectation_cleanup(expt);

							return POM_OK;
							/*
							pom_log(POM_LOG_DEBUG "Expected connection already has a target_priv from the same target. Replacing with expected one.");

							// FIXME should we try to merge both ?
							// This can only occur with TCP connection, if 'master' connection has some packet loss
							// it will receive the packet with the new connection info too late

							target_lock_instance(tp->t, 0);
							if (tp->priv && tp->cleanup_handler) {
								if ((*tp->cleanup_handler) (tp->t, f->ce, tp->priv) == POM_ERR) {
									pom_log(POM_LOG_ERR "Target %s's connection cleanup handler returned an error. Stopping it", target_get_name(tp->t->type));
									target_close(tp->t);
								}
							}
							target_unlock_instance(tp->t);

							tp->priv = expt->target_priv;
							tp->cleanup_handler = expt->target_priv_cleanup_handler;

							found_dup = 1;*/
							break;
						}

						tp = tp->next;
					}

					if (!found_dup)// Corresponding target_priv wasn't found
						conntrack_add_target_priv(expt->target_priv, expt->t, f->ce, expt->target_priv_cleanup_handler);
				}

			} else {
				conntrack_create_entry(f);
				if (expt->target_priv)
					conntrack_add_target_priv(expt->target_priv, expt->t, f->ce, expt->target_priv_cleanup_handler);
			}

			f->ce->parent_ce = expt->parent_ce;

			target_process(expt->t, f);

			expt->t->matched = 1;
			struct expectation_list *expt_next = expt->next;
			expectation_cleanup(expt);
			expt = expt_next;
			continue;

		} else {
			expt->t->matched = 0;
		}


		expt = expt->next;
	}


	return POM_OK;

}

