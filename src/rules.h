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



#ifndef __RULES_H__
#define __RULES_H__

#define RULE_OP_AND	0x1
#define RULE_OP_OR	0x2
#define RULE_OP_NOT	0x4
#define RULE_OP_TAIL	0x8

/// A rule_node containes two next node and a possible match.
struct rule_node {
	struct rule_node *a; ///< Next rule to match
	struct rule_node *b; ///< Possible other rule to match
	unsigned int op; ///< Operator (and, or, not)
	unsigned int layer; ///< Ignore if op != 0
	struct match_field *match; ///< how to match the current rule
	struct rule_node *last; ///< Last node of the branch, computed by rules

};


// We need to declare rule_node before including target.h and match.h
#include "match.h"

/// each rule_list contains the first rule_node and target
struct rule_list {
	struct rule_node *node; ///< rule node to see if we can match the packet
	struct target *target; ///< what to do if we match
	unsigned int result; ///< true if the packet has to be processed
	int enabled; ///< true if rule is enabled and has to be proccessed
	uint32_t uid; ///< unique id of the rule which changes each time it's modified

	struct ptype* pkt_cnt; ///< matched packet count
	struct ptype* byte_cnt; ///< matched byte count

	struct rule_list *next; ///< next rule in the list
	struct rule_list *prev; ///< previous rule in the list
};

#include "target.h"

int rules_init();

int rule_update(struct rule_list *rule, struct rule_list *list, uint32_t *serial);

int node_match(struct frame *f, struct layer **l, struct rule_node *n, struct rule_node *last);

int do_rules(struct frame *f, struct rule_list *rules, pthread_rwlock_t *rule_lock);

int node_destroy(struct rule_node *node, int sub);

int list_destroy(struct rule_list *list);

int rule_print_flat(struct rule_node *n, struct rule_node *last, char *buffer, size_t buff_len);

int rule_parse(char *expr, struct rule_node **start, struct rule_node **end, char *errbuff, int errlen);

#endif

