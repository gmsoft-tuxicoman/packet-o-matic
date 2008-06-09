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


int expectation_init() {

	match_undefined_id = match_register("undefined");

	return POM_OK;

}


struct expectation_list *expectation_alloc(struct frame *f, struct target *t, struct conntrack_entry *ce, int direction) {

	struct layer *l = f->l;

	if (!l)
		return NULL;

	struct expectation_list *lst = malloc(sizeof(struct expectation_list));
	memset(lst, 0, sizeof(struct expectation_list));


	lst->parent_ce = ce;
	lst->t = t;
	lst->expiry = timer_alloc(lst, f->input, expectation_do_timer);

	struct expectation_node *last_node = NULL;


	while (l && l->type != match_undefined_id) {
	
		match_refcount_inc(l->type);

		struct expectation_node *n = malloc(sizeof(struct expectation_node));
		memset(n, 0, sizeof(struct expectation_node));
		n->layer = l->type;


		int i;
		for (i = 0; l->fields[i] && i < MAX_LAYER_FIELDS; i++) {
			int field_id = match_get_expectation(l->type, i, direction);
			if (field_id != POM_ERR) {
				if (!l->fields[field_id]) {
					pom_log(POM_LOG_WARN "Warning, match_create_expectation returned an id hat doesn't correspond to a valid field_id\r\n");
					l = l->next;
					continue;
				}
				struct expectation_field *fld = malloc(sizeof(struct expectation_field));
				memset(fld, 0, sizeof(struct expectation_field));
				fld->op = PTYPE_OP_EQ;
				fld->value = ptype_alloc_from(l->fields[field_id]);
			
				struct match_field_reg *fld_reg = match_get_field(l->type, i);
				fld->name = fld_reg->name;
				fld->field_id = i;

				fld->next = n->fields;
				n->fields = fld;
			}
		}

		if (!lst->n) {
			lst->n = n;
		} else {
			last_node->next = n;
		}
		last_node = n;

		l = l->next;

	}

	return lst;
}

int expectation_set_target_priv(struct expectation_list *l, void *target_priv, int (*cleanup_handler) (struct target *t, struct conntrack_entry *ce, void *priv)) {

	if (l->target_priv) {
		pom_log(POM_LOG_WARN "Warning, target priv already set for this expectation\r\n");
		return POM_ERR;
	}
	l->target_priv = target_priv;
	l->target_priv_cleanup_handler = cleanup_handler;

	return POM_OK;

}

int expectation_add(struct expectation_list *l, unsigned int expiry) {

	if (l->next || l->prev || l == expt_head) {
		pom_log(POM_LOG_WARN "Warning, expectation already added\r\n");
		return POM_ERR;
	}
	
	if (expt_head)
		expt_head->prev = l;
	l->next = expt_head;
	expt_head = l;

	timer_queue(l->expiry, expiry);

	return POM_OK;
}

int expectation_cleanup(struct expectation_list *l) {


	if (l->prev) {
		l->prev->next = l->next;
	} else if (l == expt_head) {
		expt_head = l->next;
		if (expt_head)
			expt_head->prev = NULL;
	}

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

		struct layer *l = f->l;

		struct expectation_node *n = expt->n;

		int process = 1;

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


		if (process) {
			if (!f->ce)
				conntrack_create_entry(f);
			if (f->ce) {
				f->ce->parent_ce = expt->parent_ce;
				if (expt->target_priv)
					conntrack_add_target_priv(expt->target_priv, expt->t, f->ce, expt->target_priv_cleanup_handler);
			}

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

