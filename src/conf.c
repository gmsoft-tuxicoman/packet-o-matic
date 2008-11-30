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
#include <libxml/xmlwriter.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include <pthread.h>

#include "conf.h"
#include "input.h"
#include "target.h"
#include "match.h"
#include "conntrack.h"
#include "helper.h"
#include "ptype.h"
#include "main.h"
#include "core_param.h"
#include "mgmtsrv.h"
#include "datastore.h"
#include "ptype_bool.h"
#include "ptype_uint64.h"

struct conf *config_alloc() {

	struct conf *c;
	c = malloc(sizeof(struct conf));
	memset(c, 0, sizeof(struct conf));
	if (pthread_rwlock_init(&c->rules_lock, NULL)) {
		pom_log(POM_LOG_ERR "Unable to init the config rules lock");
		free(c);
		return NULL;
	}

	return c;

}

int config_cleanup(struct conf* c) {
	
	input_lock(0);
	input_cleanup(c->input);
	input_unlock();

	list_destroy(c->rules);

	if (pthread_rwlock_destroy(&c->rules_lock)) {
		pom_log(POM_LOG_ERR "Unable to destroy the config rules lock");
	}

	while (c->datastores) {
		struct datastore* tmp = c->datastores;
		c->datastores = tmp->next;
		datastore_close(tmp);
		datastore_cleanup(tmp);
	}

	free(c);
	return POM_OK ;
}

struct input* config_parse_input(xmlDocPtr doc, xmlNodePtr cur) {
	char *input_type;
	input_type = (char*) xmlGetProp(cur, (const xmlChar*) "type");
	if (!input_type) {
		pom_log(POM_LOG_ERR "No type given in the input tag");
		return NULL;
	}
	pom_log(POM_LOG_TSHOOT "Parsing input of type %s", input_type);

	input_lock(1);

	int it = input_register(input_type);
	if (it == POM_ERR) {
		input_unlock();
		pom_log(POM_LOG_ERR "Could not load input %s !", input_type);
		xmlFree(input_type);
		return NULL;
	}
	struct input *ip = input_alloc(it);

	// we got a refcount, we can safely unlock
	input_unlock();

	if (!ip) {
		
		pom_log(POM_LOG_ERR "Error, unable to allocate input of type %s", input_type);
		xmlFree(input_type);
		return NULL;
	}


	char *input_mode;
	input_mode = (char *) xmlGetProp(cur, (const xmlChar*) "mode");
	if (!input_mode)
		pom_log("Warning, no mode specified in the input tag. Will use the default");
	else {
		if (input_set_mode(ip, input_mode) != POM_OK) {
			pom_log(POM_LOG_ERR "Unable to set mode %s for input %s", input_type, input_mode);
			free(ip);
			xmlFree(input_type);
			xmlFree(input_mode);
			return NULL;
		}
	}

	char *input_start;
	input_start = (char *) xmlGetProp(cur, (const xmlChar*) "start");
	if (!input_start)
		ip->running = 1; // If start is not specified, start it
	else if (!strcmp(input_start, "yes"))
		ip->running = 1;
	xmlFree(input_start);

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
						pom_log(POM_LOG_ERR "Unable to parse \"%s\" for parameter %s of input %s", value, param_type, input_type);
					}
					break;
				}
				param = param->next;
			}
			if (!param) {
				if (!ip->mode)
					pom_log(POM_LOG_WARN "No parameter %s for input %s", param_type, input_type);
				else
					pom_log(POM_LOG_WARN "No parameter %s for input %s and mode %s", param_type, input_type, ip->mode->name);
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
		pom_log(POM_LOG_ERR "No type given in the target tag");
		return NULL;
	}
	pom_log(POM_LOG_TSHOOT "Parsing target of type %s", target_type);
	int tt = target_register(target_type);
	if (tt == -1) {
		pom_log(POM_LOG_ERR "Could not load target %s !", target_type);
		xmlFree(target_type);
		return NULL;
	}
	struct target *tp = target_alloc(tt);

	if (!tp) {
		pom_log(POM_LOG_ERR "Error, unable to allocate target of type %s", target_type);
		xmlFree(target_type);
		return NULL;
	}

	char *target_mode;
	target_mode = (char *) xmlGetProp(cur, (const xmlChar*) "mode");
	if (target_mode) {
		if (target_set_mode(tp, target_mode) != POM_OK) {
			pom_log(POM_LOG_ERR "No mode %s for target %s", target_mode, target_type);
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
					pom_log(POM_LOG_WARN "Error, no parameter %s for target %s", param_type, target_type);
				else
					pom_log(POM_LOG_WARN "Error, no parameter %s for target %s and mode %s", param_type, target_type, tp->mode->name);
			} else { 
				if (ptype_unserialize(value, param_value) != POM_OK) 
					pom_log(POM_LOG_ERR "Error, could not parse value %s for parameter %s for target %s", param_value, param_type, target_type);
			}

			xmlFree(param_type);
			xmlFree(param_value);

		} else if (!xmlStrcmp(pcur->name, (const xmlChar *) "description") && !tp->description) {
			char *value = (char *) xmlNodeListGetString(doc, pcur->xmlChildrenNode, 1);
			tp->description = malloc(strlen(value) + 1);
			memset(tp->description, 0, sizeof(tp->description));
			strcpy(tp->description, value);
			xmlFree(value);
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
				pom_log(POM_LOG_ERR "No layer given in the match tag");
				return NULL;
			}
			pom_log(POM_LOG_TSHOOT "Parsing match of layer %s", layer);
			match_lock(1);
			int mt = match_register(layer);
			if (mt == -1) {
				match_unlock();
				pom_log(POM_LOG_ERR "Could not load match %s !", layer);
				xmlFree(layer);
				return NULL;
			}

			n = malloc(sizeof(struct rule_node));
			memset(n, 0, sizeof(struct rule_node));
			pom_log(POM_LOG_TSHOOT "Creating new rule_node");
			n->layer = mt;
			match_refcount_inc(mt);
			match_unlock();

			char *field = (char *) xmlGetProp(cur, (const xmlChar*) "field");
			if (field) {

				char *value = (char *) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
				if (!value) {
					pom_log(POM_LOG_WARN "Field specified for match %s but no value given", layer);
					xmlFree(field);
				} else {
					struct match_field *mf = match_alloc_field(mt, field);
					if (!mf) {
						pom_log(POM_LOG_ERR "No field %s for match %s", field, layer);
					} else if (ptype_unserialize(mf->value, value) == POM_ERR) {
						pom_log(POM_LOG_ERR "Unable to parse value \"%s\" for field %s and match %s", value, field, layer);
					} else {
						n->match = mf;
						char *op = (char*) xmlGetProp(cur, (const xmlChar*) "op");
						if (!op)
							mf->op = ptype_get_op(mf->value, "==");
						else
							mf->op = ptype_get_op(mf->value, op);
						if (mf->op == POM_ERR) {
							pom_log(POM_LOG_ERR "Invalid operation %s for field %s and layer %s", op, field, layer);
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
					pom_log(POM_LOG_ERR "Invalid value for 'inv'. Should be either 'yes' or 'no'");

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
			pom_log(POM_LOG_TSHOOT "Creating new rule_node");

			char *op =(char *)  xmlGetProp(cur, (const xmlChar *)"op");
			if (op) {
				if (!strcmp(op, "and"))
					n->op = RULE_OP_AND;
				else if (!strcmp(op, "or"))
					n->op = RULE_OP_OR;
				else {
					pom_log(POM_LOG_ERR "Invalid operation %s for node", op);
					xmlFree(op);
					return NULL;
				}
				xmlFree(op);
			}

			xmlNodePtr pcur = cur->xmlChildrenNode;

			while (pcur) {
				if (!xmlStrcmp(pcur->name, (const xmlChar *) "a")  && !n->a)
					n->a = parse_match(doc, pcur->xmlChildrenNode);
				else if (!xmlStrcmp(pcur->name, (const xmlChar *) "b")  && !n->b)
					n->b = parse_match(doc, pcur->xmlChildrenNode);
				else if (xmlStrcmp(pcur->name,(const xmlChar *) "text") && xmlStrcmp(pcur->name,(const xmlChar *) "comment"))
					pom_log (POM_LOG_WARN "Error in config, duplicate or unknown tag %s", pcur->name);
				pcur = pcur->next;
						
			}
			
			char *inv = (char *) xmlGetProp(cur, (const xmlChar *)"inv");
			if (inv) {
				if (!strcmp(inv, "yes")) {
					if (n->b)
						pom_log(POM_LOG_WARN "The operation '!' is not supported on or/and operations");
					else
						n->op |= RULE_OP_NOT;
				} else if (strcmp(inv, "no")) 
					pom_log(POM_LOG_ERR "Invalid 'inv' value. Either 'yes' or 'no'");
				
					
			}
					
			xmlFree(inv);


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
				pom_log(POM_LOG_WARN "Warning, unrecognized tag <%s> inside <matches> tags", cur->name);
		}

		cur = cur->next;

	}
	return head;

}

struct rule_list *parse_rule(xmlDocPtr doc, xmlNodePtr cur) {


	struct rule_list *r;
	r = malloc(sizeof(struct rule_list));
	memset(r, 0, sizeof(struct rule_list));

	r->uid = get_uid();
	
	struct ptype *disabled_pt = ptype_alloc("bool", NULL);
	if (!disabled_pt) {
		pom_log(POM_LOG_ERR "Unable to load ptype bool !");
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
				t->parent_serial = &r->target_serial;
			}
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "matches")) {
			if (r->node)
				pom_log(POM_LOG_WARN "Only one instance of matches supported. Skipping extra instances");
			else
				r->node = parse_match(doc, cur->xmlChildrenNode);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "description")) {
			char *value = (char *) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			r->description = malloc(strlen(value) + 1);
			memset(r->description, 0, sizeof(r->description));
			strcpy(r->description, value);
			xmlFree(value);
		}

		cur = cur->next;
	}

	r->pkt_cnt = ptype_alloc("uint64", "pkts");
	r->pkt_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN;
	r->byte_cnt = ptype_alloc("uint64", "bytes");
	r->byte_cnt->print_mode = PTYPE_UINT64_PRINT_HUMAN_1024;

	return r;

}

struct datastore* config_parse_datastore(xmlDocPtr doc, xmlNodePtr cur) {


	char *datastore_type;
	datastore_type = (char*) xmlGetProp(cur, (const xmlChar*) "type");
	if (!datastore_type) {
		pom_log(POM_LOG_ERR "No type given in the datastore tag");
		xmlFree(datastore_type);
		return NULL;
	}
	
	pom_log(POM_LOG_TSHOOT "Parsing datastore of type %s", datastore_type);

	char *datastore_name;
	datastore_name = (char*) xmlGetProp(cur, (const xmlChar*) "name");
	if (!datastore_name) {
		pom_log(POM_LOG_ERR "No name given in the datastore tag");
		xmlFree(datastore_type);
		xmlFree(datastore_name);
		return NULL;
	}

	datastore_lock(1);

	int dt = datastore_register(datastore_type);
	if (dt == POM_ERR) {
		datastore_unlock();
		pom_log(POM_LOG_ERR "Could not load datastore %s !", datastore_type);
		xmlFree(datastore_type);
		xmlFree(datastore_name);
		return NULL;
	}
	struct datastore *d = datastore_alloc(dt);

	// we got a refcount, we can safely unlock
	datastore_unlock();

	if (!d) {
		
		pom_log(POM_LOG_ERR "Error, unable to allocate datastore of type %s", datastore_type);
		xmlFree(datastore_type);
		xmlFree(datastore_name);
		return NULL;
	}

	d->name = malloc(strlen(datastore_name) + 1);
	strcpy(d->name, datastore_name);

	char *datastore_start;
	datastore_start = (char *) xmlGetProp(cur, (const xmlChar*) "start");
	if (!datastore_start)
		d->started = 1; // If start is not specified, start it
	else if (!strcmp(datastore_start, "yes"))
		d->started = 1;
	xmlFree(datastore_start);

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
			struct datastore_param *param = d->params;
			while (param) {
				if (!strcmp(param->type->name, param_type)) {
					if (ptype_unserialize(param->value, value) == POM_ERR) {
						pom_log(POM_LOG_ERR "Unable to parse \"%s\" for parameter %s of datastore %s", value, param_type, datastore_type);
					}
					break;
				}
				param = param->next;
			}
			if (!param) {
				pom_log(POM_LOG_WARN "No parameter %s for datastore %s", param_type, datastore_type);
			}

			xmlFree(param_type);
			xmlFree(value);

		}
		pcur = pcur->next;
	}
	xmlFree(datastore_type);
	xmlFree(datastore_name);

	if (d->started) { // Start the datastore if needed
		d->started = 0;
		datastore_open(d);
	}

	return d;
}


int config_parse(struct conf *c, char * filename) {

	
	xmlDocPtr doc;
	xmlNodePtr root, cur;

	doc = xmlParseFile(filename);

	if (!doc) {
		pom_log(POM_LOG_ERR "Parse error when parsing %s!", filename);
		return POM_ERR;
	}

	root = xmlDocGetRootElement(doc);

	if (!root) {
		pom_log(POM_LOG_ERR "Hey dude, ya better gimme a non empty config file !");
		xmlFreeDoc(doc);
		return POM_ERR;
	}

	if (xmlStrcmp(root->name, (const xmlChar *) "config")) {
		pom_log(POM_LOG_ERR "The first node should be <config> !");
		return POM_ERR;
	}

	cur = root->xmlChildrenNode;

	while (cur) {
		if (!xmlStrcmp(cur->name, (const xmlChar *) "input")) {
			if (c->input)
				pom_log(POM_LOG_WARN "Only one input supported. Skipping extra input defined");
			else
				c->input = config_parse_input(doc, cur);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "rule")) {
			if (pthread_rwlock_wrlock(&c->rules_lock)) {
				pom_log(POM_LOG_ERR "Unable to aquire lock on the rules");
				return POM_ERR;
			}
			struct rule_list *r = parse_rule(doc, cur);
			if (!r) {
				pthread_rwlock_unlock(&c->rules_lock);
				return POM_ERR;
			}

			if (!c->rules) {
				c->rules = r;
			} else {
				struct rule_list *tmpr = c->rules;
				while (tmpr->next)
					tmpr = tmpr->next;
				tmpr->next = r;
				r->prev = tmpr;

			}
			if (pthread_rwlock_unlock(&c->rules_lock)) {
				pom_log(POM_LOG_ERR "Unable to unlock the rules");
			}
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "param")) {
			char *name = (char *) xmlGetProp(cur, (const xmlChar*) "name");
			if (name) {
				char *value = (char *) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
				if (value) {
					char buffer[2048];
					if (core_set_param_value(name, value, buffer, sizeof(buffer) - 1) == POM_ERR) {
						pom_log(POM_LOG_WARN "Unable to set parameter %s to %s : %s", name, value, buffer);
					}

					xmlFree(value);
				} else {
					pom_log(POM_LOG_WARN "Warning, no value given for parameter %s", name);
				}
				xmlFree(name);
			} else { 
				pom_log(POM_LOG_WARN "Param found but no name given");
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
				pom_log(POM_LOG_WARN "No type specified in the conntrack tag");
				cur = cur->next;
				continue;
			}
			int ct_type;
			match_lock(1);
			ct_type = match_register(type);
			match_unlock();
			if (ct_type == POM_ERR) {
				pom_log(POM_LOG_WARN "Unable to register match %s", type);
				cur = cur->next;
				xmlFree(type);
				continue;
			}
			conntrack_lock(1);
			ct_type = conntrack_register(type);
			if (ct_type == POM_ERR) {
				conntrack_unlock();
				pom_log(POM_LOG_WARN "Unable to register conntrack %s", type);
				cur = cur->next;
				xmlFree(type);
				continue;

			}

			xmlNodePtr sub = cur->xmlChildrenNode;
			while (sub) {
				if (!xmlStrcmp(sub->name, (const xmlChar *) "param")) {
					char *name = (char *) xmlGetProp(sub, (const xmlChar*) "name");
					if (!name) {
						pom_log(POM_LOG_WARN "No name given for the param tag");
						sub = sub->next;
						continue;
					}
					struct conntrack_param *param = conntrack_get_param(ct_type, name);
					if (!param) {
						pom_log(POM_LOG_WARN "No parameter %s for conntrack %s", type, name);
						sub = sub->next;
						continue;
					}
					char *value = (char *) xmlNodeListGetString(doc, sub->xmlChildrenNode, 1);
					if (value) {
						if (ptype_unserialize(param->value, value) == POM_ERR)
							pom_log(POM_LOG_WARN "Unable to parse value '%s' for parameter %s of conntrack %s", value, name, type);
					} else {
						pom_log(POM_LOG_WARN "No value given for param %s of conntrack %s", name, type);
					}


				}
				sub = sub->next;
			}
			conntrack_unlock();
			xmlFree(type);
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "datastore")) {
			struct datastore *d = config_parse_datastore(doc, cur);
			if (!c->datastores) {
				c->datastores = d;
			} else {
				struct datastore *tmp = c->datastores;
				while (tmp->next)
					tmp = tmp->next;
				tmp->next = d;
				d->prev = tmp;
			}
		} else if (!xmlStrcmp(cur->name, (const xmlChar *) "helper")) {
			char *type = (char *) xmlGetProp(cur, (const xmlChar*) "type");
			if (!type) {
				pom_log(POM_LOG_WARN "No type specified in the helper tag");
				cur = cur->next;
				continue;
			}
			int ct_type;
			match_lock(1);
			ct_type = match_register(type);
			match_unlock();
			if (ct_type == POM_ERR) {
				pom_log(POM_LOG_WARN "Unable to register match %s", type);
				cur = cur->next;
				xmlFree(type);
				continue;
			}
			helper_lock(1);
			ct_type = helper_register(type);
			if (ct_type == POM_ERR) {
				helper_unlock();
				pom_log(POM_LOG_WARN "Unable to register helper %s", type);
				cur = cur->next;
				xmlFree(type);
				continue;

			}

			xmlNodePtr sub = cur->xmlChildrenNode;
			while (sub) {
				if (!xmlStrcmp(sub->name, (const xmlChar *) "param")) {
					char *name = (char *) xmlGetProp(sub, (const xmlChar*) "name");
					if (!name) {
						pom_log(POM_LOG_WARN "No name given for the param tag");
						sub = sub->next;
						continue;
					}
					struct helper_param *param = helper_get_param(ct_type, name);
					if (!param) {
						pom_log(POM_LOG_WARN "No parameter %s for helper %s", type, name);
						sub = sub->next;
						continue;
					}
					char *value = (char *) xmlNodeListGetString(doc, sub->xmlChildrenNode, 1);
					if (value) {
						if (ptype_unserialize(param->value, value) == POM_ERR)
							pom_log(POM_LOG_WARN "Unable to parse value '%s' for parameter %s of helper %s", value, name, type);
					} else {
						pom_log(POM_LOG_WARN "No value given for param %s of helper %s", name, type);
					}


				}
				sub = sub->next;
			}
			helper_unlock();
			xmlFree(type);
		}

		cur = cur->next;
	}



	xmlFreeDoc(doc);

	xmlCleanupParser();

	strncpy(c->filename, filename, NAME_MAX);

	if (c->input && c->input->running) {
		c->input->running = 0;
		start_input(rbuf);

	}


	return POM_OK;
}

int config_write_rule(xmlTextWriterPtr writer, struct rule_node *n, struct rule_node *last, int tabs_count) {

	if (n == last)
		return 0;

	char *tabs = malloc((sizeof(char) * tabs_count) + 2);
	tabs[0] = '\n';
	memset(tabs + 1, '\t', tabs_count);
	tabs[tabs_count + 1] = 0;


	while (n != last) {

		if (!n->b) {
			if (n->op != RULE_OP_TAIL) {
				xmlTextWriterWriteString(writer, BAD_CAST tabs);	
				xmlTextWriterStartElement(writer, BAD_CAST "match");
				xmlTextWriterWriteAttribute(writer, BAD_CAST "layer", BAD_CAST match_get_name(n->layer));
				if (n->op & RULE_OP_NOT)
					xmlTextWriterWriteAttribute(writer, BAD_CAST "inv", BAD_CAST "yes");
				if (n->match) {
					char value[256];
					ptype_serialize(n->match->value, value, sizeof(value));
					struct match_field_reg *field = match_get_field(n->layer, n->match->id);
					xmlTextWriterWriteAttribute(writer, BAD_CAST "field", BAD_CAST field->name);
					if (n->match->op != PTYPE_OP_EQ) {
						xmlTextWriterWriteAttribute(writer, BAD_CAST "op", BAD_CAST ptype_get_op_name(n->match->op));
					}
					xmlTextWriterWriteString(writer, BAD_CAST value);

				} 
				xmlTextWriterEndElement(writer);
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

			xmlTextWriterWriteString(writer, BAD_CAST tabs);	
			
			xmlTextWriterStartElement(writer, BAD_CAST "node");
			char *orand = "or";
			if (n->op & RULE_OP_AND)
				orand = "and";
			xmlTextWriterWriteAttribute(writer, BAD_CAST "op", BAD_CAST orand);
			if (n->op & RULE_OP_NOT)
				xmlTextWriterWriteAttribute(writer, BAD_CAST "inv", BAD_CAST "yes");

			xmlTextWriterWriteString(writer, BAD_CAST tabs);	
			xmlTextWriterStartElement(writer, BAD_CAST "a");
			config_write_rule(writer, n->a, new_last, tabs_count + 1);
			xmlTextWriterWriteString(writer, BAD_CAST tabs);	
			xmlTextWriterEndElement(writer);

			xmlTextWriterWriteString(writer, BAD_CAST tabs);	
			xmlTextWriterStartElement(writer, BAD_CAST "b");
			config_write_rule(writer, n->b, new_last, tabs_count + 1);
			xmlTextWriterWriteString(writer, BAD_CAST tabs);	
			xmlTextWriterEndElement(writer);

			xmlTextWriterWriteString(writer, BAD_CAST tabs);	

			// </node>
			xmlTextWriterEndElement(writer);
			n = new_last;
		}
	}

	free(tabs);

	return POM_OK;
}

int config_write(struct conf *c, char *filename) {

	if (!filename)
		filename = c->filename;

	xmlTextWriterPtr writer;

	writer = xmlNewTextWriterFilename(filename, 0);
	if (!writer) {
		pom_log(POM_LOG_ERR "Error while opening config file for writing : %s");
		return POM_ERR;
	}

	int res;
	// write the header
	res = xmlTextWriterStartDocument(writer, NULL, "ISO-8859-1", NULL);
	if (res < 0) {
		return POM_ERR;	
	}

	xmlTextWriterWriteComment(writer, BAD_CAST "Packet-o-matic configuration");
	xmlTextWriterWriteFormatString(writer, "\n");

	// write the <config> element
	xmlTextWriterWriteFormatString(writer, "\n");
	xmlTextWriterStartElement(writer, BAD_CAST "config");
	xmlTextWriterWriteFormatString(writer, "\n");

	// write the password if present
	const char *passwd = mgmtsrv_get_password();
	if (passwd) {
		xmlTextWriterWriteFormatString(writer, "\n\t");
		xmlTextWriterWriteComment(writer, BAD_CAST "Management console password");
		xmlTextWriterWriteFormatString(writer, "\n\t");
		xmlTextWriterWriteElement(writer, BAD_CAST "password", BAD_CAST passwd);
	}

	// write the core parameters
	int first_param = 1;
	struct core_param *p = core_param_get_head();
	char *value = NULL;
	size_t size = 0, new_size = 64;
	while (p) {
		do {
			if (new_size > size) {
				value = realloc(value, new_size + 1);
				size = new_size;
			}
			new_size = ptype_serialize(p->value, value, size);
			new_size = (new_size < 1) ? new_size * 2 : new_size + 1;
		} while (new_size > size);

		if (strcmp(value, p->defval)) {
			if (first_param) {
				first_param = 0;
				xmlTextWriterWriteFormatString(writer, "\n\t");
				xmlTextWriterWriteComment(writer, BAD_CAST "Core parameters");
			}
			xmlTextWriterWriteFormatString(writer, "\n\t");
			xmlTextWriterStartElement(writer, BAD_CAST "param");
			xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST p->name);
			xmlTextWriterWriteString(writer, BAD_CAST value);
			xmlTextWriterEndElement(writer);
		}
		p = p->next;
	}
	if (value)
		free(value);

	if (!first_param)
		xmlTextWriterWriteFormatString(writer, "\n");

	// write the helper parameters if needed
	int i, some_helper = 0;
	helper_lock(0);
	for (i = 0; i < MAX_HELPER; i++) {
		if (helpers[i]) {
			int some_param = 0;
			struct helper_param *p = helpers[i]->params;
			while (p) {
				char value[512];
				memset(value, 0, 512);
				ptype_serialize(p->value, value, sizeof(value));
				if (strcmp(value, p->defval)) {
					if (!some_param) {
						if (!some_helper) {
							xmlTextWriterWriteFormatString(writer, "\n\n\t");
							xmlTextWriterWriteComment(writer, BAD_CAST "Helper parameters");
							some_helper = 1;
						}
						xmlTextWriterWriteFormatString(writer, "\n\t");
						xmlTextWriterStartElement(writer, BAD_CAST "helper");
						xmlTextWriterWriteAttribute(writer, BAD_CAST "type", BAD_CAST match_get_name(i));
						some_param = 1;
					}
					xmlTextWriterWriteFormatString(writer, "\n\t\t");
					xmlTextWriterStartElement(writer, BAD_CAST "param");
					xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST p->name);
					xmlTextWriterWriteString(writer, BAD_CAST value);
					xmlTextWriterEndElement(writer);

				}
				p = p->next;
			}
			if (some_param) {
				xmlTextWriterWriteFormatString(writer, "\n\t");
				xmlTextWriterEndElement(writer);
			}
		}

	}
	if (some_helper)
		xmlTextWriterWriteFormatString(writer, "\n");
	helper_unlock();

	// write the conntrack parameters if needed
	int some_conntrack = 0;
	conntrack_lock(0);
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
						if (!some_conntrack) {
							xmlTextWriterWriteFormatString(writer, "\n\n\t");
							xmlTextWriterWriteComment(writer, BAD_CAST "Conntrack parameters");
							some_conntrack = 1;
						}
						xmlTextWriterWriteFormatString(writer, "\n\t");
						xmlTextWriterStartElement(writer, BAD_CAST "conntrack");
						xmlTextWriterWriteAttribute(writer, BAD_CAST "type", BAD_CAST match_get_name(i));
						some_param = 1;
					}
					xmlTextWriterWriteFormatString(writer, "\n\t\t");
					xmlTextWriterStartElement(writer, BAD_CAST "param");
					xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST p->name);
					xmlTextWriterWriteString(writer, BAD_CAST value);
					xmlTextWriterEndElement(writer);

				}
				p = p->next;
			}
			if (some_param) {
				xmlTextWriterWriteFormatString(writer, "\n\t");
				xmlTextWriterEndElement(writer);
			}
		}

	}
	if (some_conntrack)
		xmlTextWriterWriteFormatString(writer, "\n");
	conntrack_unlock();

	// write the input config
	if (c->input) {
		xmlTextWriterWriteFormatString(writer, "\n\t");
		xmlTextWriterWriteComment(writer, BAD_CAST "Input configuration");
		xmlTextWriterWriteFormatString(writer, "\n\t");
		xmlTextWriterStartElement(writer, BAD_CAST "input");
		xmlTextWriterWriteAttribute(writer, BAD_CAST "type", BAD_CAST input_get_name(c->input->type));
		xmlTextWriterWriteAttribute(writer, BAD_CAST "mode", BAD_CAST c->input->mode->name);
		char *yesno = "no";
		if (c->input->running)
			yesno = "yes";
		xmlTextWriterWriteAttribute(writer, BAD_CAST "start", BAD_CAST yesno);

		xmlTextWriterWriteFormatString(writer, "\n\t");

		struct input_param *p = c->input->mode->params;
		while (p) {
			char value[1024];
			ptype_serialize(p->value, value, sizeof(value) - 1);
			if (strcmp(value, p->defval)) { // parameter doesn't have default value
				xmlTextWriterWriteFormatString(writer, "\t");
				xmlTextWriterStartElement(writer, BAD_CAST "param");
				xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST p->name);
				xmlTextWriterWriteString(writer, BAD_CAST value);
				xmlTextWriterEndElement(writer);
				xmlTextWriterWriteFormatString(writer, "\n\t");
			}
			p = p->next;
		}

		xmlTextWriterEndElement(writer);
		xmlTextWriterWriteFormatString(writer, "\n");
	}

	// write the datastores
	if (c->datastores) {
		struct datastore *d = c->datastores;
		xmlTextWriterWriteFormatString(writer, "\n\t");
		xmlTextWriterWriteComment(writer, BAD_CAST "Datastores configuration");
		xmlTextWriterWriteFormatString(writer, "\n\t");
		while (d) {
			xmlTextWriterStartElement(writer, BAD_CAST "datastore");
			xmlTextWriterWriteAttribute(writer, BAD_CAST "type", BAD_CAST datastore_get_name(d->type));
			xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST d->name);
			char *yesno = "no";
			if (d->started)
				yesno = "yes";
			xmlTextWriterWriteAttribute(writer, BAD_CAST "start", BAD_CAST yesno);
			xmlTextWriterWriteFormatString(writer, "\n\t");
			struct datastore_param *p = d->params;
			while (p) {
				char value[1024];
				ptype_serialize(p->value, value, sizeof(value) - 1);
				if (strcmp(value, p->type->defval)) { // parameter doesn't have default value
					xmlTextWriterWriteFormatString(writer, "\t");
					xmlTextWriterStartElement(writer, BAD_CAST "param");
					xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST p->type->name);
					xmlTextWriterWriteString(writer, BAD_CAST value);
					xmlTextWriterEndElement(writer);
					xmlTextWriterWriteFormatString(writer, "\n\t");
				}
				p = p->next;
			}

			xmlTextWriterEndElement(writer);
			xmlTextWriterWriteFormatString(writer, "\n\t");
			d = d->next;
		}
	}

	// write the rules
	
	struct rule_list *rl = c->rules;


	if (pthread_rwlock_rdlock(&c->rules_lock)) {
		pom_log(POM_LOG_ERR "Unable to aquire the lock on the rules");
		return POM_ERR;
	}

	if (rl) {
		xmlTextWriterWriteFormatString(writer, "\n\t");
		xmlTextWriterWriteComment(writer, BAD_CAST "Rules definition");
	}
	while (rl) {
		
		xmlTextWriterWriteFormatString(writer, "\n\t");
		xmlTextWriterStartElement(writer, BAD_CAST "rule");
		if (!rl->enabled)
			xmlTextWriterWriteAttribute(writer, BAD_CAST "disabled", BAD_CAST "yes");

		if (rl->description) {
			xmlTextWriterWriteFormatString(writer, "\n\t\t");
			xmlTextWriterWriteElement(writer, BAD_CAST "description", BAD_CAST rl->description);
		}

		struct target *t = rl->target;
		while (t) {
			xmlTextWriterWriteFormatString(writer, "\n\t\t");
			xmlTextWriterStartElement(writer, BAD_CAST "target");
			xmlTextWriterWriteAttribute(writer, BAD_CAST "type", BAD_CAST target_get_name(t->type));
			char *yesno = "no";
			if (t->started)
				yesno = "yes";
			xmlTextWriterWriteAttribute(writer, BAD_CAST "start", BAD_CAST yesno);

			if (t->mode) {
				xmlTextWriterWriteAttribute(writer, BAD_CAST "mode", BAD_CAST t->mode->name);
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
						xmlTextWriterWriteFormatString(writer, "\n\t\t\t");
						xmlTextWriterStartElement(writer, BAD_CAST "param");
						xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST tp->type->name);
						xmlTextWriterWriteString(writer, BAD_CAST value);
						xmlTextWriterEndElement(writer);
					}
		
					tpr = tpr->next;
				}

			} 

			if (t->description) {
				xmlTextWriterWriteFormatString(writer, "\n\t\t\t");
				xmlTextWriterWriteElement(writer, BAD_CAST "description", BAD_CAST t->description);
			}

			xmlTextWriterWriteFormatString(writer, "\n\t\t");
			xmlTextWriterEndElement(writer);

			t = t->next;

		}

		xmlTextWriterWriteFormatString(writer, "\n\t\t");
		xmlTextWriterStartElement(writer, BAD_CAST "matches");

		config_write_rule(writer, rl->node, NULL, 3);

		// </matches>
		xmlTextWriterWriteFormatString(writer, "\n\t\t");
		xmlTextWriterEndElement(writer);

		// </rules>
		xmlTextWriterWriteFormatString(writer, "\n\t");
		xmlTextWriterEndElement(writer);
		
		rl = rl->next;
	}
	xmlTextWriterWriteFormatString(writer, "\n\n");

	if (pthread_rwlock_unlock(&c->rules_lock)) {
		pom_log(POM_LOG_ERR "Unable to unlock the rules lock");
		return POM_ERR;
	}

	// finish the config

	xmlTextWriterEndElement(writer);
	xmlTextWriterWriteFormatString(writer, "\n\n");
	xmlTextWriterEndDocument(writer);
	xmlFreeTextWriter(writer);
	xmlCleanupCharEncodingHandlers();
	xmlCleanupParser();

	if (c->filename != filename)
		strncpy(c->filename, filename, NAME_MAX);

	return POM_OK;


}
