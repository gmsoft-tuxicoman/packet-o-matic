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

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include "conf.h"
#include "input.h"
#include "target.h"
#include "match.h"
#include "conntrack.h"
#include "helper.h"
#include "ptype.h"
#include "main.h"
#include "mgmtsrv.h"
#include "ptype_bool.h"
#include "ptype_uint64.h"

struct conf *config_alloc() {

	struct conf *c;
	c = malloc(sizeof(struct conf));
	memset(c, 0, sizeof(struct conf));
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
		pom_log(POM_LOG_ERR "No type given in the input tag\r\n");
		return NULL;
	}
	pom_log(POM_LOG_TSHOOT "Parsing input of type %s\r\n", input_type);
	int it = input_register(input_type);
	if (it == POM_ERR) {
		pom_log(POM_LOG_ERR "Could not load input %s !\r\n", input_type);
		xmlFree(input_type);
		return NULL;
	}
	struct input *ip = input_alloc(it);
	if (!ip) {
		
		pom_log(POM_LOG_ERR "Error, unable to allocate input of type %s\r\n", input_type);
		xmlFree(input_type);
		return NULL;
	}

	char *input_mode;
	input_mode = (char *) xmlGetProp(cur, (const xmlChar*) "mode");
	if (!input_mode)
		pom_log("Warning, no mode specified in the input tag. Will use the default\r\n");
	else {
		if (input_set_mode(ip, input_mode) != POM_OK) {
			pom_log(POM_LOG_ERR "Unable to set mode %s for input %s\r\n", input_type, input_mode);
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
					if (ptype_unserialize(param->value, value) == POM_ERR) {
						pom_log(POM_LOG_ERR "Unable to parse \"%s\" for parameter %s of input %s\r\n", value, param_type, input_type);
					}
					break;
				}
				param = param->next;
			}
			if (!param) {
				if (!ip->mode)
					pom_log(POM_LOG_WARN "No parameter %s for input %s\r\n", param_type, input_type);
				else
					pom_log(POM_LOG_WARN "No parameter %s for input %s and mode %s\r\n", param_type, input_type, ip->mode->name);
			}

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
		pom_log(POM_LOG_ERR "No type given in the target tag\r\n");
		return NULL;
	}
	pom_log(POM_LOG_TSHOOT "Parsing target of type %s\r\n", target_type);
	int tt = target_register(target_type);
	if (tt == -1) {
		pom_log(POM_LOG_ERR "Could not load target %s !\r\n", target_type);
		xmlFree(target_type);
		return NULL;
	}
	struct target *tp = target_alloc(tt);

	if (!tp) {
		pom_log(POM_LOG_ERR "Error, unable to allocate target of type %s\r\n", target_type);
		xmlFree(target_type);
		return NULL;
	}

	char *target_mode;
	target_mode = (char *) xmlGetProp(cur, (const xmlChar*) "mode");
	if (target_mode) {
		if (target_set_mode(tp, target_mode) != POM_OK) {
			pom_log(POM_LOG_ERR "No mode %s for target %s\r\n", target_mode, target_type);
			free(tp);
			xmlFree(target_type);
			xmlFree(target_mode);
			return NULL;
		}
	}

	xmlFree(target_mode);

	xmlNodePtr pcur = cur->xmlChildrenNode;
	while (pcur) {
		if (!xmlStrcmp(pcur->name, (const xmlChar*) "param")) {
			char *param_type = (char *) xmlGetProp(pcur, (const xmlChar*) "name");
			if (!param_type)
				continue;
			char *param_value = (char *) xmlNodeListGetString(doc, pcur->xmlChildrenNode, 1);
			if (!param_value) {
				xmlFree(param_type);
				continue;
			}
			
			struct ptype *value = target_get_param_value(tp, param_type);
			if (!value) {
				if (!tp->mode)
					pom_log(POM_LOG_WARN "Error, no parameter %s for target %s\r\n", param_type, target_type);
				else
					pom_log(POM_LOG_WARN "Error, no parameter %s for target %s and mode %s\r\n", param_type, target_type, tp->mode->name);
			} else { 
				if (ptype_unserialize(value, param_value) != POM_OK) 
					pom_log(POM_LOG_ERR "Error, could not parse value %s for parameter %s for target %s\r\n", param_value, param_type, target_type);
			}

			xmlFree(param_type);
			xmlFree(param_value);

		}
		pcur = pcur->next;
	}
	xmlFree(target_type);

	char *target_start = (char *) xmlGetProp(cur, (const xmlChar*) "start");
	if (!target_start || !strcmp(target_start, "yes"))
		target_open(tp);
	
	if (target_start)
		xmlFree(target_start);

	return tp;



}

struct rule_node *parse_match(xmlDocPtr doc, xmlNodePtr cur) {

	struct rule_node *head = NULL, *tail = NULL;

	while (cur) {

		struct rule_node *n = NULL;

		if (!xmlStrcmp(cur->name, (const xmlChar *) "match")) {
			
			
			char *layer = (char *) xmlGetProp(cur, (const xmlChar*) "layer");
			if (!layer) {
				pom_log(POM_LOG_ERR "No layer given in the match tag\r\n");
				return NULL;
			}
			pom_log(POM_LOG_TSHOOT "Parsing match of layer %s\r\n", layer);
			int mt = match_register(layer);
			if (mt == -1) {
				pom_log(POM_LOG_ERR "Could not load match %s !\r\n", layer);
				xmlFree(layer);
				return NULL;
			}

			n = malloc(sizeof(struct rule_node));
			memset(n, 0, sizeof(struct rule_node));
			pom_log(POM_LOG_TSHOOT "Creating new rule_node\r\n");
			n->layer = mt;
			match_refcount_inc(mt);

			char *field = (char *) xmlGetProp(cur, (const xmlChar*) "field");
			if (field) {

				char *value = (char *) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
				if (!value) {
					pom_log(POM_LOG_WARN "Field specified for match %s but no value given\r\n", layer);
					xmlFree(field);
				} else {
					struct match_field *mf = match_alloc_field(mt, field);
					if (!mf) {
						pom_log(POM_LOG_ERR "No field %s for match %s\r\n", field, layer);
					} else if (ptype_unserialize(mf->value, value) == POM_ERR) {
						pom_log(POM_LOG_ERR "Unable to parse value \"%s\" for field %s and match %s\r\n", value, field, layer);
					} else {
						n->match = mf;
						char *op = (char*) xmlGetProp(cur, (const xmlChar*) "op");
						if (!op)
							mf->op = ptype_get_op(mf->value, "==");
						else
							mf->op = ptype_get_op(mf->value, op);
						if (mf->op == POM_ERR) {
							pom_log(POM_LOG_ERR "Invalid operation %s for field %s and layer %s\r\n", op, field, layer);
							free(mf);
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
					pom_log(POM_LOG_ERR "Invalid value for 'inv'. Should be either 'yes' or 'no'\r\n");

			}
					
			xmlFree(inv);
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
			memset(n, 0, sizeof(struct rule_node));
			pom_log(POM_LOG_TSHOOT "Creating new rule_node\r\n");

			char *op =(char *)  xmlGetProp(cur, (const xmlChar *)"op");
			if (op) {
				if (!strcmp(op, "and"))
					n->op = RULE_OP_AND;
				else if (!strcmp(op, "or"))
					n->op = RULE_OP_OR;
				else {
					pom_log(POM_LOG_ERR "Invalid operation %s for node\r\n", op);
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
					pom_log(POM_LOG_ERR "Invalid 'inv' value. Either 'yes' or 'no'\r\n");
				
					
			}
					
			xmlFree(inv);

			xmlNodePtr pcur = cur->xmlChildrenNode;

			while (pcur) {
				if (!xmlStrcmp(pcur->name, (const xmlChar *) "a")  && !n->a)
					n->a = parse_match(doc, pcur->xmlChildrenNode);
				else if (!xmlStrcmp(pcur->name, (const xmlChar *) "b")  && !n->b)
					n->b = parse_match(doc, pcur->xmlChildrenNode);
				else if (xmlStrcmp(pcur->name,(const xmlChar *) "text") && xmlStrcmp(pcur->name,(const xmlChar *) "comment"))
					pom_log (POM_LOG_WARN "Error in config, duplicate or unknown tag %s\r\n", pcur->name);
				pcur = pcur->next;
						
			}
			

			// Attach the last node of each part to one single now
			struct rule_node *tmpn, *nextn;
			nextn = malloc(sizeof(struct rule_node));
			memset(nextn, 0, sizeof(struct rule_node));
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
				pom_log(POM_LOG_WARN "Warning, unrecognized tag <%s> inside <matches> tags\r\n", cur->name);
		}

		cur = cur->next;

	}
	return head;

}

struct rule_list *parse_rule(xmlDocPtr doc, xmlNodePtr cur) {


	struct rule_list *r;
	r = malloc(sizeof(struct rule_list));
	memset(r, 0, sizeof(struct rule_list));
	
	struct ptype *disabled_pt = ptype_alloc("bool", NULL);
	if (!disabled_pt) {
		pom_log(POM_LOG_ERR "Unable to load ptype bool !\r\n");
		return NULL;
	}

	char *disabled = (char *) xmlGetProp(cur, (const xmlChar*) "disabled");
	if (disabled) {
		ptype_unserialize(disabled_pt, disabled);
		r->enabled = !PTYPE_BOOL_GETVAL(disabled_pt);
	} else
		r->enabled = 1;
	xmlFree(disabled);

	ptype_cleanup(disabled_pt);

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
					t->prev = tmpt;
				}		
			}
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "matches")) {
			if (r->node)
				pom_log(POM_LOG_WARN "Only one instance of matches supported. Skipping extra instances\r\n");
			else
				r->node = parse_match(doc, cur->xmlChildrenNode);
		}

		cur = cur->next;
	}

	r->pkt_cnt = ptype_alloc("uint64", "pkts");
	r->pkt_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN;
	r->byte_cnt = ptype_alloc("uint64", "bytes");
	r->byte_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN;

	return r;

}


int config_parse(struct conf *c, char * filename) {

	
	xmlDocPtr doc;
	xmlNodePtr root, cur;

	doc = xmlParseFile(filename);

	if (!doc) {
		pom_log(POM_LOG_ERR "Parse error when parsing %s!\r\n", filename);
		return POM_ERR;
	}

	root = xmlDocGetRootElement(doc);

	if (!root) {
		pom_log(POM_LOG_ERR "Hey dude, ya better gimme a non empty config file !\r\n");
		xmlFreeDoc(doc);
		return POM_ERR;
	}

	if (xmlStrcmp(root->name, (const xmlChar *) "config")) {
		pom_log(POM_LOG_ERR "The first node should be <config> !\r\n");
		return POM_ERR;
	}

	cur = root->xmlChildrenNode;

	while (cur) {
		if (!xmlStrcmp(cur->name, (const xmlChar *) "input")) {
			if (c->input)
				pom_log(POM_LOG_WARN "Only one input supported. Skipping extra input defined\r\n");
			else
				c->input = config_parse_input(doc, cur);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "rule")) {
			struct rule_list *r = parse_rule(doc, cur);
			if (!r)
				return POM_ERR;

			if (!c->rules) {
				c->rules = r;
			} else {
				struct rule_list *tmpr = c->rules;
				while (tmpr->next)
					tmpr = tmpr->next;
				tmpr->next = r;
				r->prev = tmpr;

			}
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "param")) {
			char *name = (char *) xmlGetProp(cur, (const xmlChar*) "name");
			if (name) {
				char *value = (char *) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
				if (value) {
					char buffer[2048];
					if (core_set_param_value(name, value, buffer, sizeof(buffer) - 1) == POM_ERR) {
						pom_log(POM_LOG_WARN "Unable to set parameter %s to %s : %s\r\n", name, value, buffer);
					}

					xmlFree(value);
				} else {
					pom_log(POM_LOG_WARN "Warning, no value given for parameter %s\r\n", name);
				}
				xmlFree(name);
			} else { 
				pom_log(POM_LOG_WARN "Param found but no name given\r\n");
			}

		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "password")) {
			char *passwd = (char *) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			if (passwd) {
				mgmtsrv_set_password(passwd);
				xmlFree(passwd);
			}
			
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "conntrack")) {
			char *type = (char *) xmlGetProp(cur, (const xmlChar*) "type");
			if (!type) {
				pom_log(POM_LOG_WARN "No type specified in the conntrack tab\r\n");
				cur = cur->next;
				continue;
			}
			int ct_type;
			ct_type = match_register(type);
			if (ct_type == POM_ERR) {
				pom_log(POM_LOG_WARN "Unable to register match %s\r\n", type);
				cur = cur->next;
				xmlFree(type);
				continue;
			}
			ct_type = conntrack_register(type);
			if (ct_type == POM_ERR) {
				pom_log(POM_LOG_WARN "Unable to register conntrack %s\r\n", type);
				cur = cur->next;
				xmlFree(type);
				continue;

			}

			xmlNodePtr sub = cur->xmlChildrenNode;
			while (sub) {
				if (!xmlStrcmp(sub->name, (const xmlChar *) "param")) {
					char *name = (char *) xmlGetProp(sub, (const xmlChar*) "name");
					if (!name) {
						pom_log(POM_LOG_WARN "No name given for the param tag\r\n");
						sub = sub->next;
						continue;
					}
					struct conntrack_param *param = conntrack_get_param(ct_type, name);
					if (!param) {
						pom_log(POM_LOG_WARN "No parameter %s for conntrack %s\r\n", type, name);
						sub = sub->next;
						continue;
					}
					char *value = (char *) xmlNodeListGetString(doc, sub->xmlChildrenNode, 1);
					if (value) {
						if (ptype_unserialize(param->value, value) == POM_ERR)
							pom_log(POM_LOG_WARN "Unable to parse value '%s' for parameter %s of conntrack %s\r\n", value, name, type);
					} else {
						pom_log(POM_LOG_WARN "No value given for param %s of conntrack %s\r\n", name, type);
					}


				}
				sub = sub->next;
			}
			xmlFree(type);
		}

		cur = cur->next;
	}



	xmlFreeDoc(doc);

	xmlCleanupParser();

	strncpy(c->filename, filename, NAME_MAX);

	return POM_OK;
}

int config_write_rule(int fd, struct rule_node *n, struct rule_node *last, int tabs) {

	if (n == last)
		return 0;

	char buffer[2048];
	memset(buffer, 0, sizeof(buffer));

	int i;

	while (n != last) {

		if (!n->b) {
			if (n->op != RULE_OP_TAIL) {
				for (i = 0; i < tabs; i++)
					strcat(buffer, "\t");
			
				strcat(buffer, "<match layer=\"");
				strcat(buffer, match_get_name(n->layer));
				strcat(buffer, "\"");
				if (n->op & RULE_OP_NOT)
					strcat(buffer, " inv=\"yes\"");
				if (n->match) {
					char value[256];
					ptype_serialize(n->match->value, value, sizeof(value));
					strcat(buffer, " field=\"");
					struct match_field_reg *field = match_get_field(n->layer, n->match->id);
					strcat(buffer, field->name);
					strcat(buffer, "\"");
					if (n->match->op != PTYPE_OP_EQ) {
						strcat(buffer, " op=\"");
						strcat(buffer, ptype_get_op_name(n->match->op));
						strcat(buffer, "\"");
					}
					strcat(buffer, ">");
					strcat(buffer, value);
					strcat(buffer, "</match>\n");

				} else
					strcat(buffer, "/>\n");
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

			for (i = 0; i < tabs; i++)
				strcat(buffer, "\t");
			strcat(buffer, "<node op=\"");
			if (n->op & RULE_OP_OR)
				strcat(buffer, "or");
			else if (n->op & RULE_OP_AND)
				strcat(buffer, "and");
			strcat(buffer, "\"");
			if (n->op & RULE_OP_NOT)
				strcat(buffer, " inv=\"yes\"");
			strcat(buffer, ">\n");

			for (i = 0; i < tabs; i++)
				strcat(buffer, "\t");

			strcat(buffer, "<a>\n");
			if (write(fd, buffer, strlen(buffer)) == -1)
				goto err;
			memset(buffer, 0, sizeof(buffer));
			
			config_write_rule(fd, n->a, new_last, tabs + 1);

			for (i = 0; i < tabs; i++)
				strcat(buffer, "\t");
			strcat(buffer, "</a>\n");
			for (i = 0; i < tabs; i++)
				strcat(buffer, "\t");
			strcat(buffer, "<b>\n");
			if (write(fd, buffer, strlen(buffer)) == -1)
				goto err;
			memset(buffer, 0, sizeof(buffer));

			config_write_rule(fd, n->b, new_last, tabs + 1);

			for (i = 0; i < tabs; i++)
				strcat(buffer, "\t");
			strcat(buffer, "</b>\n");

			for (i = 0; i < tabs; i++)
				strcat(buffer, "\t");

			strcat(buffer, "</node>\n");
			n = new_last;
		}
	}

	if (write(fd, buffer, strlen(buffer)) == -1)
		goto err;

	return POM_OK;

err:
	close(fd);
	char errbuff[256];
	strerror_r(errno, errbuff, sizeof(errbuff));
	pom_log(POM_LOG_ERR "Error while writing the config file : %s\r\n", errbuff);
	return POM_ERR;
}

int config_write(struct conf *c, char *filename) {

	if (!filename)
		filename = c->filename;

	int fd;
	fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

	if (fd == -1) {
		char buffer[256];
		strerror_r(errno, buffer, sizeof(buffer) - 1);
		pom_log(POM_LOG_ERR "Error while opening config file for writing : %s\r\n", buffer);
		return POM_ERR;
	}

	// write the header and first <config> tag

	char buffer[4096]; // each element will not be 2048 bytes long
	memset(buffer, 0, sizeof(buffer));
	strcat(buffer, "<?xml version=\"1.0\"?>\n<config>\n\n");

	// write the password if present
	const char *passwd = mgmtsrv_get_password();
	if (passwd) {
		strcat(buffer, "<password>");
		strcat(buffer, passwd);
		strcat(buffer, "</password>\n\n");
	}

	// write the core parameters
	struct core_param *p = core_params;
	while (p) {
		char value[1024];
		ptype_serialize(p->value, value, sizeof(value) - 1);
		if (strcmp(value, p->defval)) {
			strcat(buffer, "<param name=\"");
			strcat(buffer, p->name);
			strcat(buffer, "\">");
			strcat(buffer, value);
			strcat(buffer, "</param>\n");
		}
		p = p->next;
	}
	strcat(buffer, "\n\n");

	if (write(fd, buffer, strlen(buffer)) == -1)
		goto err;
	memset(buffer, 0, sizeof(buffer));

	// write the conntrack parameters if needed
	int i;
	for (i = 0; i < MAX_CONNTRACK; i++) {
		if (conntracks[i]) {
			int some_param = 0;
			struct conntrack_param *p = conntracks[i]->params;
			while (p) {
				char value[512];
				memset(value, 0, 512);
				ptype_serialize(p->value, value, sizeof(value));
				if (strcmp(value, p->defval)) {
					if (!some_param) {
						strcat(buffer, "<conntrack type=\"");
						strcat(buffer, match_get_name(i));
						strcat(buffer, "\">\n");
						some_param = 1;
					}
					strcat(buffer, "\t<param name=\"");
					strcat(buffer, p->name);
					strcat(buffer, "\">");
					strcat(buffer, value);
					strcat(buffer, "</param>\n");


				}
				p = p->next;
			}
			if (some_param) {
				strcat(buffer, "</conntrack>\n\n");
				if (write(fd, buffer, strlen(buffer)) == -1)
					goto err;
				memset(buffer, 0, sizeof(buffer));
			}
		}

	}

	// write the input config
	if (c->input) {
		strcat(buffer, "<input type=\"");
		strcat(buffer, input_get_name(c->input->type));
		strcat(buffer, "\" mode=\"");
		strcat(buffer, c->input->mode->name);
		strcat(buffer, "\">\n");

		struct input_param *p = c->input->mode->params;
		while (p) {
			char value[1024];
			ptype_serialize(p->value, value, sizeof(value) - 1);
			if (strcmp(value, p->defval)) { // parameter doesn't have default value
				strcat(buffer, "\t<param name=\"");
				strcat(buffer, p->name);
				strcat(buffer, "\">");
				strcat(buffer, value);
				strcat(buffer, "</param>\n");
			}
			p = p->next;
		}

		strcat(buffer, "</input>\n\n");
	}

	if (write(fd, buffer, strlen(buffer)) == -1)
		goto err;
	memset(buffer, 0, sizeof(buffer));

	// write the rules
	
	struct rule_list *rl = c->rules;

	while (rl) {
		
		strcat(buffer, "<rule");
		if (!rl->enabled)
			strcat(buffer, " disabled=\"yes\"");
		strcat(buffer, ">\n");

		struct target *t = rl->target;
		while (t) {
			strcat(buffer, "\t<target type=\"");
			strcat(buffer, target_get_name(t->type));
			strcat(buffer, "\" start=\"");
			if (t->started)
				strcat(buffer, "yes");
			else
				strcat(buffer, "no");
			strcat(buffer, "\"");

			if (t->mode) {
				strcat(buffer, " mode=\"");
				strcat(buffer, t->mode->name);
				strcat(buffer, "\">\n");
				struct target_param_reg *tpr = t->mode->params;
				while (tpr) {
					
					struct target_param *tp = t->params;
					while (tp) {
						if (tp->type == tpr)
							break;
						tp = tp->next;
					}
				
					if (!tp)
						continue;

					char value[1024];
					ptype_serialize(tp->value, value, sizeof(value) - 1);
					if (strcmp(value, tp->type->defval)) {
						strcat(buffer, "\t\t<param name=\"");
						strcat(buffer, tp->type->name);
						strcat(buffer, "\">");
						strcat(buffer, value);
						strcat(buffer, "</param>\n");
					}
		
					tpr = tpr->next;
				}

				strcat(buffer, "\t</target>\n\n");
			} else
				strcat(buffer, "/>\n");

			t = t->next;

			if (write(fd, buffer, strlen(buffer)) == -1)
				goto err;
			memset(buffer, 0, sizeof(buffer));
		}

		strcat(buffer, "\t<matches>\n");

		if (write(fd, buffer, strlen(buffer)) == -1)
			goto err;
		memset(buffer, 0, sizeof(buffer));

		config_write_rule(fd, rl->node, NULL, 2);

		strcat(buffer, "\t</matches>\n");

		strcat(buffer, "</rule>\n\n");
		
		rl = rl->next;
	}

	// finish the config

	strcat(buffer, "</config>\n");

	if (write(fd, buffer, strlen(buffer)) == -1)
		goto err;

	close(fd);

	if (c->filename != filename)
		strncpy(c->filename, filename, NAME_MAX);

	return POM_OK;


err:
	close(fd);
	char errbuff[256];
	strerror_r(errno, errbuff, sizeof(errbuff));
	pom_log(POM_LOG_ERR "Error while writing the config file : %s\r\n", errbuff);
	return POM_ERR;

}
