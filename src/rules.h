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



struct rule_node {
	struct rule_node *a; // next rule to match
	struct rule_node *b; // possible other rule to match
	struct match *match; // How to match the current rule

};


// We need to declare rule_node before including target.h and match.h
#include "match.h"
#include "target.h"


struct rule_list {
	struct rule_list *next; // next rule to process in the list
	struct rule_node *node; // rule node to see if we can match the packet
	struct target *target; // what to do if we match
	unsigned int result; // true if the packet has to be processed
};

int rules_init();

int do_rules(void *frame, unsigned int start, unsigned int len, struct rule_list *rules, int first_layer);

int node_destroy(struct rule_node *node, int sub);

int list_destroy(struct rule_list *list);



#endif

