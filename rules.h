

#ifndef __RULES_H__
#define __RULES_H__


#define RULE_OP_AND	0
#define RULE_OP_OR	1



struct rule_node {
	struct rule_node *a; // next rule to match
	struct rule_node *b; // possible other rule to match
	int andor; // and = 1; or = 0; // operator to apply if b exists
	struct match *match; // How to match the current rule

};


// We need to declare rule_node before including target.h and match.h
#include "match.h"
#include "target.h"


struct rule_list {
	struct rule_list *next; // next rule to process in the list
	struct rule_node *node; // rule node to see if we can match the packet
	struct target *target; // what to do if we match
};


int do_rules(void *frame, unsigned int start, unsigned int len, struct rule_list *rules, int first_layer);

unsigned int node_find_header_start(struct rule_node *node, int header_type);

int node_match(void *frame, unsigned int start, unsigned int len, struct rule_node *node);

int node_destroy(struct rule_node *node);

int list_destroy(struct rule_list *list);



#endif

