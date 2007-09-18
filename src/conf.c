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
#include "ptype.h"

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
	if (it == I_ERR) {
		dprint("Could not load input %s !\n", input_type);
		xmlFree(input_type);
		return NULL;
	}
	struct input *ip = input_alloc(it);
	char *input_mode;
	input_mode = (char *) xmlGetProp(cur, (const xmlChar*) "mode");
	if (!input_mode)
		dprint("Warning, no mode specified in the input tag. Will use the default\n");
	else {
		if (input_set_mode(ip, input_mode) != I_OK) {
			dprint("Unable to set mode %s for input %s\n", input_type, input_mode);
			free(ip);
			xmlFree(input_type);
			xmlFree(input_mode);
			return NULL;
		}
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
			struct input_param *param = ip->mode->params;
			while (param) {
				if (!strcmp(param->name, param_type)) {
					if (ptype_parse_val(param->value, value) == P_ERR) {
						dprint("Unable to parse \"%s\" for parameter %s of input %s\n", value, param_type, input_type);
					}
					break;
				}
				param = param->next;
			}
			if (!param)
				dprint("No parameter %s for input %s and mode %s\n", param_type, input_type, input_mode);

			xmlFree(param_type);
			xmlFree(value);

		}
		pcur = pcur->next;
	}
	xmlFree(input_mode);
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
			
			
			char *layer = (char *) xmlGetProp(cur, (const xmlChar*) "layer");
			if (!layer) {
				dprint("No layer given in the match tag\n");
				return NULL;
			}
			ndprint("Parsing match of layer %s\n", match_type);
			int mt = match_register(layer);
			if (mt == -1) {
				dprint("Could not load match %s !\n", layer);
				xmlFree(layer);
				return NULL;
			}

			n = malloc(sizeof(struct rule_node));
			bzero(n, sizeof(struct rule_node));
			ndprint("Creating new rule_node\n");
			n->layer = mt;

			char *field = (char *) xmlGetProp(cur, (const xmlChar*) "field");
			if (field) {

				char *value = (char *) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
				if (!value) {
					dprint("Field specified for match %s but no value given\n", layer);
					xmlFree(field);
				} else {
					struct match_param *mp = match_alloc_param(mt, field);
					if (ptype_parse_val(mp->value, value) == POM_ERR) {
						dprint("Unable to parse value \"%s\" for field %s and match %s\n", value, field, layer);
					} else {
						n->match = mp;
						char *op = (char*) xmlGetProp(cur, (const xmlChar*) "op");
						if (!op)
							mp->op = ptype_get_op(mp->value, "==");
						else
							mp->op = ptype_get_op(mp->value, op);
						if (mp->op == P_ERR) {
							dprint("Invalid operation %s for field %s and layer %s\n", op, field, layer);
							free(mp);
							n->match = NULL;
						}
						xmlFree(op);

					}
					xmlFree(value);
					xmlFree(field);
				}
			}

			char *inv = (char *) xmlGetProp(cur, (const xmlChar *)"inv");
			if (inv) {
				if (!strcmp(inv, "yes"))
					n->op |= RULE_OP_NOT;
				else if (strcmp(inv, "no"))
					dprint("Invalid value for 'inv'. Should be either 'yes' or 'no'.\n");

			}
					
			xmlFree(inv);

			// Try to register corresponding conntrack and helper
			conntrack_register(layer);
			helper_register(layer);

			xmlFree(layer);
			// Add the new node at the right place
			if (!head)
				head = n;
			if (!tail)
				tail = n;
			else {
				tail->a = n;
				tail = n;
			}


		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "node")) {
			// This match the following
			// <node op="someop" inv="yes"><a>some match</a><b>some match</b></node>


			n = malloc(sizeof(struct rule_node));
			bzero(n, sizeof(struct rule_node));
			ndprint("Creating new rule_node\n");

			char *op =(char *)  xmlGetProp(cur, (const xmlChar *)"op");
			if (op) {
				if (!strcmp(op, "and"))
					n->op = RULE_OP_AND;
				else if (!strcmp(op, "or"))
					n->op = RULE_OP_OR;
				else {
					dprint("Invalid operation %s for node.\n", op);
					xmlFree(op);
					return NULL;
				}
				xmlFree(op);
			}

			char *inv = (char *) xmlGetProp(cur, (const xmlChar *)"inv");
			if (inv) {
				if (!strcmp(inv, "yes"))
					n->op |= RULE_OP_NOT;
				else if (strcmp(inv, "no")) 
					dprint("Invalid 'inv' value. Either 'yes' or 'no'\n");
				
					
			}
					
			xmlFree(inv);

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
			nextn->op = RULE_OP_TAIL;

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
				if (!r->target)
					r->target = t;
				else {
					struct target *tmpt = r->target;
					while (tmpt->next)
						tmpt = tmpt->next;
					tmpt->next = t;
				}		
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
