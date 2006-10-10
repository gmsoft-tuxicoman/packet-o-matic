#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include "conf.h"
#include "input.h"
#include "target.h"
#include "match.h"
#include "conntrack.h"

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
	xmlChar *input_type;
	input_type = xmlGetProp(cur, "type");
	if (!input_type) {
		dprint("No type given in the input tag\n");
		return NULL;
	}
	dprint("Parsing input of type %s\n", input_type);
	int it = input_register(input_type);
	if (it == -1) {
		dprint("Input %s not supported\n", input_type);
		xmlFree(input_type);
		return NULL;
	}
	struct input *ip = input_alloc(it);
	xmlNodePtr pcur = cur->xmlChildrenNode;
	while (pcur) {
		if (!xmlStrcmp(pcur->name, (const xmlChar*) "param")) {
			xmlChar *param_type = xmlGetProp(pcur, "name");
			if (!param_type)
				continue;
			xmlChar *value = xmlNodeListGetString(doc, pcur->xmlChildrenNode, 1);
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

	
	xmlChar *target_type;
	target_type = xmlGetProp(cur, "type");
	if (!target_type) {
		dprint("No type given in the target tag\n");
		return NULL;
	}
	dprint("Parsing target of type %s\n", target_type);
	int tt = target_register(target_type);
	if (tt == -1) {
		dprint("Target %s not supported\n", target_type);
		xmlFree(target_type);
		return NULL;
	}
	struct target *tp = target_alloc(tt);
	xmlNodePtr pcur = cur->xmlChildrenNode;
	while (pcur) {
		if (!xmlStrcmp(pcur->name, (const xmlChar*) "param")) {
			xmlChar *param_type = xmlGetProp(pcur, "name");
			if (!param_type)
				continue;
			xmlChar *value = xmlNodeListGetString(doc, pcur->xmlChildrenNode, 1);
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


	if (!cur)
		return NULL;




	while (cur) {
		if (!xmlStrcmp(cur->name, (const xmlChar *) "match")) {
			
			
			xmlChar *match_type = xmlGetProp(cur, "type");
			if (!match_type) {
				dprint("No type given in the match tag\n");
				return NULL;
			}
			dprint("Parsing match of type %s\n", match_type);
			int mt = match_register(match_type);
			if (mt == -1) {
				dprint("Match %s not supported\n", match_type);
				xmlFree(match_type);
				return NULL;
			}
			struct match *mp = match_alloc(mt);

			struct rule_node *n;
			n = malloc(sizeof(struct rule_node));
			bzero(n, sizeof(struct rule_node));
			ndprint("Creating new rule_node\n");

			n->match = mp;

			xmlNodePtr pcur = cur->xmlChildrenNode;
			while (pcur) {
				if (!xmlStrcmp(pcur->name, (const xmlChar*) "param")) {
					xmlChar *param_type = xmlGetProp(pcur, "name");
					if (!param_type)
						continue;
					xmlChar *value = xmlNodeListGetString(doc, pcur->xmlChildrenNode, 1);
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

			// Try to register corresponding conntrack
			conntrack_register(match_type);

			xmlFree(match_type);

			n->a = parse_match(doc, cur->next);
			return n;
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "node")) {
			xmlChar* op = xmlGetProp(cur, "op");
			if (!op) {
				dprint("No op specified in node tag\n");
				return NULL;
			}

			struct rule_node *n;
			n = malloc(sizeof(struct rule_node));
			bzero(n, sizeof(struct rule_node));
			ndprint("Creating new rule_node\n");

			if (!xmlStrcmp(op, "or"))
				n->andor = RULE_OP_OR;
			else if (!xmlStrcmp(op, "and" ))
				n->andor = RULE_OP_AND;
			else {
				dprint("Invalid operation %s for node\n", op);
				xmlFree(op);
				free(n);
				return NULL;
			}

			xmlFree(op);


			xmlNodePtr pcur = cur->xmlChildrenNode;

			while (!pcur) {
				if (!xmlStrcmp(cur->name, (const xmlChar *) "node") || !xmlStrcmp(cur->name, (const xmlChar *) "match")) {
					if (!n->a)
						n->a = parse_match(doc, pcur);
					else if (!n->b)
						n->b = parse_match(doc, pcur);
					else {
						dprint ("Too many sub nodes in node\n");
						return NULL;
					}
				}
				pcur = pcur->next;
						
			}
		
			return n;
		}
		cur = cur->next;

	}

	return NULL;

}

struct rule_list *parse_rule(xmlDocPtr doc, xmlNodePtr cur) {


	struct rule_list *r;
	r = malloc(sizeof(struct rule_list));
	bzero(r, sizeof(struct rule_list));
	
	cur = cur->xmlChildrenNode;

	while (cur) {
		if (!xmlStrcmp(cur->name, (const xmlChar *) "target")) {
			if (r->target)
				dprint("Only one target supported. Skipping extra target defined\n");
			else
				r->target = parse_target(doc, cur);
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
