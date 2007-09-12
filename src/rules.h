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



#ifndef __RULES_H__
#define __RULES_H__

#define RULE_OP_AND	0x1
#define RULE_OP_OR	0x2
#define RULE_OP_NOT	0x4
#define RULE_OP_TAIL	0x8

/// a rule_node containes two next node and a possible match
struct rule_node {
	struct rule_node *a; ///< next rule to match
	struct rule_node *b; ///< possible other rule to match
	unsigned int op; ///< operator (and, or, not)
	unsigned int layer; ///< ignore if op != 0
	struct match_param *match; ///< how to match the current rule

};


// We need to declare rule_node before including target.h and match.h
#include "match.h"

/// each rule_list contains the first rule_node and target
struct rule_list {
	struct rule_list *next; ///< next rule to process in the list
	struct rule_node *node; ///< rule node to see if we can match the packet
	struct target *target; ///< what to do if we match
	unsigned int result; ///< true if the packet has to be processed
};

#include "target.h"

int rules_init();

/// Recursively walk trough the rule_node tree and return 1 if the current frame match
int node_match(struct frame *f, struct rule_node *n, struct layer *l);

int do_rules(struct frame *f, struct rule_list *rules);

int node_destroy(struct rule_node *node, int sub);

int list_destroy(struct rule_list *list);



#endif

