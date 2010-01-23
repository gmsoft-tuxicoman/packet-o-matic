/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2009-2010 Guy Martin <gmsoft@tuxicoman.be>
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

#include "snmpagent.h"
#include "target.h"
#include "snmpcmd_target.h"
#include "snmpcmd_rules.h"
#include "main.h"
#include "perf.h"


int snmpcmd_target_init_oids(oid *base_oid, int base_oid_len) {

	oid my_oid[MAX_OID_LEN];
	memcpy(my_oid, base_oid, base_oid_len * sizeof(oid));
	my_oid[base_oid_len] = 4;

	// Register target handler
	my_oid[base_oid_len + 1] = 1;
	netsnmp_handler_registration *target_handler = netsnmp_create_handler_registration("target", snmpcmd_target_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);

	if (!target_handler)
		return POM_OK;

	netsnmp_table_registration_info *target_table_info = malloc(sizeof(netsnmp_table_registration_info));
	memset(target_table_info, 0, sizeof(netsnmp_table_registration_info));

	netsnmp_table_helper_add_indexes(target_table_info, ASN_INTEGER, ASN_INTEGER, 0);
	target_table_info->min_column = 1;
	target_table_info->max_column = 7;

	netsnmp_register_table(target_handler, target_table_info);

	// Register target param handler
	my_oid[base_oid_len + 1] = 2;
	netsnmp_handler_registration *target_param_handler = netsnmp_create_handler_registration("targetParam", snmpcmd_target_param_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);

	if (!target_param_handler)
		return POM_OK;

	netsnmp_table_registration_info *target_param_table_info = malloc(sizeof(netsnmp_table_registration_info));
	memset(target_param_table_info, 0, sizeof(netsnmp_table_registration_info));

	netsnmp_table_helper_add_indexes(target_param_table_info, ASN_INTEGER, ASN_INTEGER, ASN_INTEGER, 0);
	target_param_table_info->min_column = 1;
	target_param_table_info->max_column = 8;

	netsnmp_register_table(target_param_handler, target_param_table_info);

	// Register targets serial handler
	my_oid[base_oid_len + 1] = 3;
	netsnmp_handler_registration *target_serial_handler = netsnmp_create_handler_registration("targetSerial", snmpcmd_target_serial_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RONLY);
	netsnmp_register_instance(target_serial_handler);
	return POM_OK;

}

static unsigned int snmpcmd_target_find_next(struct target *t, struct target **next) {

	uint32_t cur_uid = 0;
	if (*next)
		cur_uid = (*next)->uid;

	*next = NULL;

	unsigned int target_id = 0, next_target_id = 0;
	while (t) {
		if (t->uid > cur_uid && (!*next || t->uid < (*next)->uid)) {
			*next = t;
			next_target_id = target_id;
		}
		t = t->next;
		target_id++;
	}

	return next_target_id;
}

int snmpcmd_target_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	while (requests) {
		netsnmp_variable_list *var = requests->requestvb;
		if (requests->processed != 0) {
			requests = requests->next;
			continue;
		}

		netsnmp_table_request_info *table_info = netsnmp_extract_table_info(requests);
		if (!table_info) {
			requests = requests->next;
			continue;
		}

		// Process SET_RESERVE1
		if (reqinfo->mode == MODE_SET_RESERVE1) {

			switch (table_info->colnum) {
				case 5:
					if (requests->requestvb->type != ASN_OCTET_STR)
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
					break;
				case 6:
					if (requests->requestvb->type != ASN_INTEGER)
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
					break;

				default:
					netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
			}
				
			requests = requests->next;
			continue;
		}

		// Get rid of useless modes
		if (reqinfo->mode != MODE_GETNEXT && reqinfo->mode != MODE_GET && reqinfo->mode != MODE_SET_ACTION) {
			requests = requests->next;
			continue;
		}

		main_config_rules_lock(0);

		if (!main_config->rules) {
			main_config_rules_unlock();
			requests = requests->next;
			continue;
		}

		// Find the right rule and target
		uint32_t rule_uid = *(table_info->indexes->val.integer);

		struct rule_list *r = main_config->rules;
		while (r && r->uid != rule_uid) {
			r = r->next;
		}

		// Find the right target

		uint32_t target_uid = *(table_info->indexes->next_variable->val.integer);
		uint32_t target_id = 0;
		struct target *t = NULL;

		if (r) {
			t = r->target;
			while (t && t->uid != target_uid) {
				t = t->next;
				target_id++;
			}
		}

		// Find the next item
		if (reqinfo->mode == MODE_GETNEXT) {
			if (rule_uid == 0 || !r) { // Get first rule
				r = NULL;
				snmpcmd_rules_find_next(main_config->rules, &r);
				t = r->target;
			}

			if (target_uid == 0) { // Get the first target
				t = NULL;
				snmpcmd_target_find_next(r->target, &t);
			} else { // Get the next target
				snmpcmd_target_find_next(r->target, &t);
				if (!t) { // Got the end of the target, next rule, first target
					snmpcmd_rules_find_next(main_config->rules, &r);
					if (!r) { // Last rule, back to first rule with first target and next colnum
						r = NULL;
						snmpcmd_rules_find_next(main_config->rules, &r);
						snmpcmd_target_find_next(r->target, &t);
						table_info->colnum++;
					} else { // First target of next rule
						t = NULL;
						snmpcmd_target_find_next(r->target, &t);
					}
				}
			}
		}

		if (!r || !t || table_info->colnum > 7) {
			if (reqinfo->mode == MODE_SET_ACTION) 
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOSUCHNAME);
			requests = requests->next;
			main_config_rules_unlock();
			continue;
		}

		if (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GET) {

			target_lock_instance(t, 0);

			unsigned char type = ASN_NULL;
			char *value = NULL;
			size_t len = 0;

			switch(table_info->colnum) {
				case 1: // Rule Index
					type = ASN_UNSIGNED;
					value = (char *)&r->uid;
					len = sizeof(r->uid);
					break;

				case 2: // Target Index
					type = ASN_UNSIGNED;
					value = (char *)&t->uid;
					len = sizeof(t->uid);
					break;
				
				case 3: // CLI Index
					type = ASN_UNSIGNED;
					value = (char *)&target_id;
					len = sizeof(target_id);
					break;

				case 4: // Type
					type = ASN_OCTET_STR;
					value = target_get_name(t->type);
					len = strlen(value);
					break;

				case 5: // Description
					type = ASN_OCTET_STR;
					if (t->description) {
						value = t->description;
						len = strlen(value);
					} else {
						value = "";
						len = 0;
					}
					break;
				
				case 6: // Started
					type = ASN_INTEGER;
					int started = 1;
					if (!t->started)
						started = 2;
					value = (char *)&started;
					len = sizeof(started);
					break;

				case 7: // Serial
					type = ASN_COUNTER;
					value = (char *)&t->serial;
					len = sizeof(t->serial);
					break;

			}

			target_unlock_instance(t);

			if (reqinfo->mode == MODE_GETNEXT) {
				*(table_info->indexes->val.integer) = r->uid;
				*(table_info->indexes->next_variable->val.integer) = t->uid;
				netsnmp_table_build_result(reginfo, requests, table_info, type, (unsigned char *)value, len);
			} else if (reqinfo->mode == MODE_GET && var->type == ASN_NULL) {
				snmp_set_var_typed_value(var, type, (unsigned char*)value, len);
			}
		} else if (reqinfo->mode == MODE_SET_ACTION) {

			target_lock_instance(t, 1);
		
			switch (table_info->colnum) {
				case 5: { // Target description
					char *new_descr = (char*)requests->requestvb->val.string;
					if (t->description)
						free(t->description);
					t->description = strdup(new_descr);
					main_config->target_serial++;
					r->target_serial++;
					t->serial++;
					break;
				}

				case 6: { // Target started
					int run = *requests->requestvb->val.integer;
					if (run == 1) {
						if (t->started) {
							netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
							pom_log(POM_LOG_DEBUG "Target already started");
						} else {
							if (target_open(t) != POM_OK) {
								netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
								pom_log(POM_LOG_DEBUG, "Error while starting the target");
							}
						}
					} else if (run == 2) {
						if (!t->started) {
							netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
							pom_log(POM_LOG_DEBUG "Target already stopped");
						} else {
							if (target_close(t) != POM_OK) {
								netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
								pom_log(POM_LOG_DEBUG, "Error while stopping the target");
							}
						}
					} else {
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
					}
					break;

				}
			}

			target_unlock_instance(t);
		}

		main_config_rules_unlock();

		requests = requests->next;
	}


	return SNMP_ERR_NOERROR;
}

int snmpcmd_target_param_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {


	while (requests) {
		netsnmp_variable_list *var = requests->requestvb;
		if (requests->processed != 0) {
			requests = requests->next;
			continue;
		}

		netsnmp_table_request_info *table_info = netsnmp_extract_table_info(requests);
		if (!table_info) {
			requests = requests->next;
			continue;
		}

		// Process SET_RESERVE1
		if (reqinfo->mode == MODE_SET_RESERVE1) {

			switch (table_info->colnum) {
				case 5:
					if (requests->requestvb->type != ASN_OCTET_STR)
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
					break;
				default:
					netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
			}
				
			requests = requests->next;
			continue;
		}

		// Get rid of useless modes
		if (reqinfo->mode != MODE_GETNEXT && reqinfo->mode != MODE_GET && reqinfo->mode != MODE_SET_ACTION) {
			requests = requests->next;
			continue;
		}

		main_config_rules_lock(0);

		if (!main_config->rules) {
			main_config_rules_unlock();
			requests = requests->next;
			continue;
		}

		// Find the right rule and target
		uint32_t rule_uid = *(table_info->indexes->val.integer);

		struct rule_list *r = main_config->rules;
		while (r && r->uid != rule_uid) {
			r = r->next;
		}

		// Find the right target

		uint32_t target_uid = *(table_info->indexes->next_variable->val.integer);
		struct target *t = NULL;
		struct target_param *tp = NULL;

		uint32_t target_param_id = *(table_info->indexes->next_variable->next_variable->val.integer);

		if (r) {
			t = r->target;
			while (t && t->uid != target_uid)
				t = t->next;
			
			// Find the right param
			if (t) {
				tp = t->params;
				int i;
				for (i = 1; tp && i < target_param_id; i++)
					tp = tp->next;

			}
		}

		// Find the next item
		if (reqinfo->mode == MODE_GETNEXT) {
			if (rule_uid == 0 || !r) { // Get first rule
				r = NULL;
				snmpcmd_rules_find_next(main_config->rules, &r);
				t = r->target;
				tp = t->params;
			}

			if (target_uid == 0) { // Get the first target
				t = NULL;
				snmpcmd_target_find_next(r->target, &t);
				if (t) {
					tp = t->params;
					target_param_id = 1;
				}
			} else {
				// Get the next target parameter
				tp = tp->next;
				target_param_id++;
				if (!tp) {
					// Get the next target
					snmpcmd_target_find_next(r->target, &t);
					if (!t) { // Got the end of the target, next rule, first target, first param
						snmpcmd_rules_find_next(main_config->rules, &r);
						if (!r) { // Last rule, back to first rule with first targeti, first param and next colnum
							r = NULL;
							snmpcmd_rules_find_next(main_config->rules, &r);
							snmpcmd_target_find_next(r->target, &t);
							table_info->colnum++;
						} else { // First target of next rule
							t = NULL;
							snmpcmd_target_find_next(r->target, &t);
						}
					} 
					
					if (t) {
						target_param_id = 1;
						tp = t->params;
					}
				}
			}
		}

		if (!r || !t || !tp || table_info->colnum > 8) {
			if (reqinfo->mode == MODE_SET_ACTION) 
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOSUCHNAME);
			requests = requests->next;
			main_config_rules_unlock();
			continue;
		}

		if (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GET) {

			target_lock_instance(t, 0);

			unsigned char type = ASN_NULL;
			char *value = NULL;
			size_t len = 0;

			switch(table_info->colnum) {
				case 1: // Rule Index
					type = ASN_UNSIGNED;
					value = (char *)&r->uid;
					len = sizeof(r->uid);
					break;

				case 2: // Target Index
					type = ASN_UNSIGNED;
					value = (char *)&t->uid;
					len = sizeof(t->uid);
					break;
				
				case 3: // Param Index
					type = ASN_UNSIGNED;
					value = (char *)&target_param_id;
					len = sizeof(target_param_id);
					break;

				case 4: // Param name
					type = ASN_OCTET_STR;
					value = tp->type->name;
					len = strlen(value);
					break;

				case 5: // Param value
					type = ASN_OCTET_STR;
					value = ptype_print_val_alloc(tp->value);
					len = strlen(value);
					break;
				
				case 6: // Param unit
					type = ASN_OCTET_STR;
					value = tp->value->unit;
					len = strlen(value);
					break;

				case 7: // Param type
					type = ASN_OCTET_STR;
					value = ptype_get_name(tp->value->type);
					len = strlen(value);
					break;

				case 8: // Param descr
					type = ASN_OCTET_STR;
					value = tp->type->descr;
					len = strlen(value);
					break;

			}

			target_unlock_instance(t);

			if (reqinfo->mode == MODE_GETNEXT) {
				*(table_info->indexes->val.integer) = r->uid;
				*(table_info->indexes->next_variable->val.integer) = t->uid;
				*(table_info->indexes->next_variable->next_variable->val.integer) = target_param_id;
				netsnmp_table_build_result(reginfo, requests, table_info, type, (unsigned char *)value, len);
			} else if (reqinfo->mode == MODE_GET && var->type == ASN_NULL) {
				snmp_set_var_typed_value(var, type, (unsigned char*)value, len);
			}

			if (table_info->colnum == 5) // value was allocated earlier
				free(value);

		} else if (reqinfo->mode == MODE_SET_ACTION) {

			char *new_val = (char*)requests->requestvb->val.string;

			target_lock_instance(t, 1);

			if (table_info->colnum != 5) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
			} else if (t->started) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
			} else if (ptype_parse_val(tp->value, new_val) != POM_OK) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
				pom_log(POM_LOG_DEBUG "You need to stop the target before doing any change");
			} else if (ptype_parse_val(tp->value, new_val) != POM_OK) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
			} else {
				main_config->target_serial++;
				r->target_serial++;
				t->serial++;
			}

			target_unlock_instance(t);
		}

		main_config_rules_unlock();

		requests = requests->next;
	}


	return SNMP_ERR_NOERROR;
}

int snmpcmd_target_serial_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {
	
	if (reqinfo->mode == MODE_GET)
		snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER, (unsigned char*) &main_config->target_serial, sizeof(main_config->rules_serial));

	return SNMP_ERR_NOERROR;
}
