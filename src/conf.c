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

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "conf.h"
#include "input.h"
#include "target.h"
#include "match.h"
#include "conntrack.h"
#include "helper.h"

struct conf *config_alloc() {

	struct conf *c;
	c = malloc(sizeof(struct conf));
	bzero(c, sizeof(struct conf));
	return c;

}

int config_cleanup(struct conf* c) {

	input_cleanup(c->input);
	list_destroy(c->rules);

	free(c);
	return 1;
}

struct input* config_parse_input(xmlDocPtr doc, xmlNodePtr cur) {
	char *input_type;
	input_type = (char*) xmlGetProp(cur, (const xmlChar*) "type");
	if (!input_type) {
		dprint("No type given in the input tag\n");
		return NULL;
	}
	ndprint("Parsing input of type %s\n", input_type);
	int it = input_register(input_type);
	if (it == -1) {
		dprint("Could not load input %s !\n", input_type);
		xmlFree(input_type);
		return NULL;
	}
	struct input *ip = input_alloc(it);
	xmlNodePtr pcur = cur->xmlChildrenNode;
	while (pcur) {
		if (!xmlStrcmp(pcur->name, (const xmlChar*) "param")) {
			char *param_type = (char *) xmlGetProp(pcur, (const xmlChar*) "name");
			if (!param_type)
				continue;
			char *value = (char *) xmlNodeListGetString(doc, pcur->xmlChildrenNode, 1);
			if (!value) {
				xmlFree(param_type);
				continue;
			}
			if (!input_set_param(ip, param_type, value))
				dprint("No parameter %s for input %s\n", param_type, input_type);

			xmlFree(param_type);
			xmlFree(value);

		}
		pcur = pcur->next;
	}
	xmlFree(input_type);

	return ip;
}

struct target *parse_target(xmlDocPtr doc, xmlNodePtr cur) {

	
	char *target_type;
	target_type = (char*) xmlGetProp(cur, (const xmlChar*) "type");
	if (!target_type) {
		dprint("No type given in the target tag\n");
		return NULL;
	}
	ndprint("Parsing target of type %s\n", target_type);
	int tt = target_register(target_type);
	if (tt == -1) {
		dprint("Could not load target %s !\n", target_type);
		xmlFree(target_type);
		return NULL;
	}
	struct target *tp = target_alloc(tt);

	if (!tp) {
		dprint("Error, unable to allocate target of type %s\n", target_type);
		xmlFree(target_type);
		return NULL;
	}

	xmlNodePtr pcur = cur->xmlChildrenNode;
	while (pcur) {
		if (!xmlStrcmp(pcur->name, (const xmlChar*) "param")) {
			char *param_type = (char *) xmlGetProp(pcur, (const xmlChar*) "name");
			if (!param_type)
				continue;
			char *value = (char *) xmlNodeListGetString(doc, pcur->xmlChildrenNode, 1);
			if (!value) {
				xmlFree(param_type);
				continue;
			}
			if (!target_set_param(tp, param_type, value))
				dprint("No parameter %s for target %s\n", param_type, target_type);

			xmlFree(param_type);
			xmlFree(value);

		}
		pcur = pcur->next;
	}
	xmlFree(target_type);

	target_open(tp);

	return tp;



}

struct rule_node *parse_match(xmlDocPtr doc, xmlNodePtr cur) {

	struct rule_node *head = NULL, *tail = NULL;

	while (cur) {

		struct rule_node *n = NULL;

		if (!xmlStrcmp(cur->name, (const xmlChar *) "match")) {
			
			
			char *match_type = (char *) xmlGetProp(cur, (const xmlChar*) "type");
			if (!match_type) {
				dprint("No type given in the match tag\n");
				return NULL;
			}
			ndprint("Parsing match of type %s\n", match_type);
			int mt = match_register(match_type);
			if (mt == -1) {
				dprint("Could not load match %s !\n", match_type);
				xmlFree(match_type);
				return NULL;
			}
			struct match *mp = match_alloc(mt);

			n = malloc(sizeof(struct rule_node));
			bzero(n, sizeof(struct rule_node));
			ndprint("Creating new rule_node\n");

			n->match = mp;

			xmlNodePtr pcur = cur->xmlChildrenNode;
			while (pcur) {
				if (!xmlStrcmp(pcur->name, (const xmlChar*) "param")) {
					char *param_type = (char *) xmlGetProp(pcur, (const xmlChar*) "name");
					if (!param_type)
						continue;
					char *value = (char *) xmlNodeListGetString(doc, pcur->xmlChildrenNode, 1);
					if (!value) {
						xmlFree(param_type);
						continue;
					}
					if (!match_set_param(mp, param_type, value))
						dprint("No parameter %s for match %s\n", param_type, match_type);

					xmlFree(param_type);
					xmlFree(value);

				}
				pcur = pcur->next;
			}

			// Try to register corresponding conntrack and helper
			conntrack_register(match_type);
			helper_register(match_type);

			xmlFree(match_type);
			// Add the new node at the right place
			if (!head)
				head = n;
			if (!tail)
				tail = n;
			else {
				tail->a = n;
				tail = n;
			}


		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "or")) {
			// This match the following
			// <or><a>some match</a><b>some match</b></or>


			n = malloc(sizeof(struct rule_node));
			bzero(n, sizeof(struct rule_node));
			ndprint("Creating new rule_node\n");

			xmlNodePtr pcur = cur->xmlChildrenNode;

			while (pcur) {
				if (!xmlStrcmp(pcur->name, (const xmlChar *) "a")  && !n->a)
					n->a = parse_match(doc, pcur->xmlChildrenNode);
				else if (!xmlStrcmp(pcur->name, (const xmlChar *) "b")  && !n->b)
					n->b = parse_match(doc, pcur->xmlChildrenNode);
				else if (xmlStrcmp(pcur->name,(const xmlChar *) "text") && xmlStrcmp(pcur->name,(const xmlChar *) "comment"))
					dprint ("Error in config, duplicate or unknown tag %s\n", pcur->name);
				pcur = pcur->next;
						
			}
			

			// Attach the last node of each part to one single now
			struct rule_node *tmpn, *nextn;
			nextn = malloc(sizeof(struct rule_node));
			bzero(nextn, sizeof(struct rule_node));

			if (n->a && n->b) {  // both matched
				tmpn = n->a;
				while (tmpn->a)
					tmpn = tmpn->a;
				tmpn->a = nextn;
				tmpn = n->b;
				while (tmpn->a)
					tmpn = tmpn->a;
				tmpn->a = nextn;
			} else if (!n->a || !n->b) { // one node was empty
				if (n->a)
					nextn = n->a;
				else if (n->b)
					nextn = n->b;
				else
					nextn = NULL;
				free(n);
				free(nextn);
				n = nextn;
			} 

			if (n) { // Add the new nodes at the right place
				if (!head && !tail) {
					head = n;
					tail = nextn;
				} else {
					tail->a = n;
					tail = nextn;
				}
			}
		
		} else {
			if (xmlStrcmp(cur->name,(const xmlChar *) "text") && xmlStrcmp(cur->name,(const xmlChar *) "comment"))
				dprint("Warning, unrecognized tag <%s> inside <matches> tags\n", cur->name);
		}

		cur = cur->next;

	}
	return head;

}

struct rule_list *parse_rule(xmlDocPtr doc, xmlNodePtr cur) {


	struct rule_list *r;
	r = malloc(sizeof(struct rule_list));
	bzero(r, sizeof(struct rule_list));
	
	cur = cur->xmlChildrenNode;

	while (cur) {
		if (!xmlStrcmp(cur->name, (const xmlChar *) "target")) {
			struct target *t = parse_target(doc, cur);
			if (t) {
				t->next = r->target;
				r->target = t;
			}
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "matches")) {
			if (r->node)
				dprint("Only one instance of matches supported. Skipping extra instances\n");
			else
				r->node = parse_match(doc, cur->xmlChildrenNode);
		}

		cur = cur->next;
	}

	return r;

}


int config_parse(struct conf *c, char * filename) {

	
	xmlDocPtr doc;
	xmlNodePtr root, cur;

	doc = xmlParseFile(filename);

	if (!doc) {
		dprint("Parse error when parsing %s!\n", filename);
		return 0;
	}

	root = xmlDocGetRootElement(doc);

	if (!root) {
		dprint("Hey dude, ya better gimme a non empty config file !\n");
		xmlFreeDoc(doc);
		return 0;
	}

	if (xmlStrcmp(root->name, (const xmlChar *) "config")) {
		dprint("The first node should be config !\n");
		return 0;
	}

	cur = root->xmlChildrenNode;

	while (cur) {
		if (!xmlStrcmp(cur->name, (const xmlChar *) "input")) {
			if (c->input)
				dprint("Only one input supported. Skipping extra input defined\n");
			else
				c->input = config_parse_input(doc, cur);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "rule")) {
			struct rule_list *r = parse_rule(doc, cur);
			r->next = c->rules;
			c->rules = r;
		}

		cur = cur->next;
	}



	xmlFreeDoc(doc);

	xmlCleanupParser();

	return 1;
}
