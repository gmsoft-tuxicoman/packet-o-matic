/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2009 Guy Martin <gmsoft@tuxicoman.be>
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
#include "snmpcmd_rules.h"
#include "main.h"
#include "rules.h"
#include "perf.h"
#include "version.h"

int snmpcmd_rules_init_oids(oid *base_oid, int base_oid_len) {

	oid my_oid[MAX_OID_LEN];
	memcpy(my_oid, base_oid, base_oid_len * sizeof(oid));
	my_oid[base_oid_len] = 3;

	// Register rules handler
	my_oid[base_oid_len + 1] = 1;
	netsnmp_handler_registration *rules_handler = netsnmp_create_handler_registration("rules", snmpcmd_rules_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);

	if (!rules_handler)
		return POM_ERR;

	netsnmp_table_registration_info *rules_table_info = malloc(sizeof(netsnmp_table_registration_info));
	memset(rules_table_info, 0, sizeof(netsnmp_table_registration_info));

	netsnmp_table_helper_add_indexes(rules_table_info, ASN_INTEGER, 0);
	rules_table_info->min_column = 1;
	rules_table_info->max_column = 5;

	netsnmp_register_table(rules_handler, rules_table_info);

	// Register rules perf handler
	my_oid[base_oid_len + 1] = 2;
	my_oid[base_oid_len + 2] = 1;
	netsnmp_handler_registration *rules_perf_handler = netsnmp_create_handler_registration("rules_perf", snmpcmd_rules_perf_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);

	if (!rules_perf_handler)
		return POM_ERR;

	netsnmp_table_registration_info *rules_perf_table_info = malloc(sizeof(netsnmp_table_registration_info));
	memset(rules_perf_table_info, 0, sizeof(netsnmp_table_registration_info));

	netsnmp_table_helper_add_indexes(rules_perf_table_info, ASN_INTEGER, 0);
	rules_perf_table_info->min_column = 1;
	rules_perf_table_info->max_column = 4;

	netsnmp_register_table(rules_perf_handler, rules_perf_table_info);

	return POM_OK;
}

static unsigned int snmpcmd_rules_find_next(struct rule_list *r, struct rule_list **next) {

	uint32_t cur_uid = 0;
	if (*next)
		cur_uid = (*next)->uid;

	*next = NULL;

	unsigned int rule_id = 0, next_rule_id = 0;
	while (r) {
		if (r->uid > cur_uid && (!*next || r->uid < (*next)->uid)) {
			*next = r;
			next_rule_id = rule_id;
		}
		r = r->next;
		rule_id++;
	}

	return next_rule_id;
}

int snmpcmd_rules_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {


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
			// Set only allowed on values
			switch (table_info->colnum) {
			
				case 3:
				case 4:
					if (requests->requestvb->type != ASN_OCTET_STR)
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
					break;
				case 5:
					if (requests->requestvb->type != ASN_INTEGER)
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
					break;

				default :
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

		if (reqinfo->mode == MODE_SET_ACTION)
			main_config_rules_lock(1);
		else
			main_config_rules_lock(0);


		// Find the right rule
		uint32_t rule_uid = *(table_info->indexes->val.integer);
		uint32_t rule_id = 0;
		struct rule_list *r = main_config->rules;
		while (r && r->uid != rule_uid) {
			r = r->next;
			rule_id++;
		}

		// Wrong rule id and get next -> start from begining
		if (reqinfo->mode == MODE_GETNEXT) {
			if (rule_uid == 0) {
				r = NULL;
				rule_id = snmpcmd_rules_find_next(main_config->rules, &r);
			} else {
	                        rule_id = snmpcmd_rules_find_next(main_config->rules, &r);
				if (!r) {
					rule_id = snmpcmd_rules_find_next(main_config->rules, &r);
					table_info->colnum++;
				}
			}
		}

		if (!r || table_info->colnum > 5) {
			requests = requests->next;
			main_config_rules_unlock();
			continue;
		}

		if (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GET) {
			unsigned char type = ASN_NULL;
			char *value = NULL;
			size_t len = 0;

			switch(table_info->colnum) {
				case 1: // Index
					type = ASN_UNSIGNED;
					value = (char *)&r->uid;
					len = sizeof(r->uid);
					break;

				case 2: // CLI Index
					type = ASN_UNSIGNED;
					value = (char *)&rule_id;
					len = sizeof(rule_id);
					break;

				case 3: // Definition
					type = ASN_OCTET_STR;
					char rule[4096];
					memset(rule, 0, sizeof(rule));
					rule_print_flat(r->node, NULL, rule, sizeof(rule) - 1);
					value = rule;
					len = strlen(rule);
					break;

				case 4: // Description
					type = ASN_OCTET_STR;
					if (r->description) {
						value = r->description;
						len = strlen(r->description);
					} else {
						value = "";
						len = 0;
					}
					break;

				case 5: // Enabled
					type = ASN_INTEGER;
					int enabled = 1;
					if (!r->enabled)
						enabled = 2;
					value = (char *)&enabled;
					len = sizeof(enabled);
					break;
					
			}

			if (reqinfo->mode == MODE_GETNEXT) {
				*(table_info->indexes->val.integer) = r->uid;
				netsnmp_table_build_result(reginfo, requests, table_info, type, (unsigned char *)value, len);

			} else if (reqinfo->mode == MODE_GET && var->type == ASN_NULL) {
				snmp_set_var_typed_value(var, type, (unsigned char*)value, len);
			}


		} else if (reqinfo->mode == MODE_SET_ACTION) {

			switch (table_info->colnum) {
				case 3: {
					char *rule_str = (char*)requests->requestvb->val.string;
					struct rule_node *start, *end;
					char errbuff[256];
					memset(errbuff, 0, sizeof(errbuff));
					if (rule_parse(rule_str, &start, &end, errbuff, sizeof(errbuff) - 1) == POM_ERR) {
						node_destroy(start, 0);
						pom_log(POM_LOG_DEBUG "Unable to parse the rule : %s", errbuff);
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
					} else {
						if (r->node)
							node_destroy(r->node, 0);
						r->node = start;
						main_config->rules_serial++;
						r->serial++;
					}
					break;
				}

				case 4: {
					char *new_descr = (char*)requests->requestvb->val.string;
					if (r->description)
						free(r->description);
					r->description = strdup(new_descr);
					main_config->rules_serial++;
					r->serial++;
					break;
				}

				case 5: {
					int run = *requests->requestvb->val.integer;
					if (run == 1) {
						if (r->enabled) {
							netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
							pom_log(POM_LOG_DEBUG "Rule already enabled");
						} else {
							rule_list_enable(r);
							main_config->rules_serial++;
							r->serial++;
						}
					} else if (run == 2) {
						if (!r->enabled) {
							netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
							pom_log(POM_LOG_DEBUG "Rule already disabled");
						} else {
							rule_list_disable(r);
							main_config->rules_serial++;
							r->serial++;
						}

					} else {
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
					}
					break;

				}

				default :
					netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);

			}

		}

		main_config_rules_unlock();

		requests = requests->next;
	}

	return SNMP_ERR_NOERROR;

}

int snmpcmd_rules_perf_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {


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

		// Get rid of useless modes
		if (reqinfo->mode != MODE_GETNEXT && reqinfo->mode != MODE_GET) {
			requests = requests->next;
			continue;
		}

		main_config_rules_lock(0);


		// Find the right rule
		uint32_t rule_uid = *(table_info->indexes->val.integer);
		uint32_t rule_id = 0;
		struct rule_list *r = main_config->rules;
		while (r && r->uid != rule_uid) {
			r = r->next;
			rule_id++;
		}

		// Wrong rule id and get next -> start from begining
		if (reqinfo->mode == MODE_GETNEXT) {
			if (rule_uid == 0) {
				r = NULL;
				rule_id = snmpcmd_rules_find_next(main_config->rules, &r);
			} else {
	                        rule_id = snmpcmd_rules_find_next(main_config->rules, &r);
				if (!r) {
					rule_id = snmpcmd_rules_find_next(main_config->rules, &r);
					table_info->colnum++;
				}
			}
		}

		if (!r || table_info->colnum > 4) {
			requests = requests->next;
			main_config_rules_unlock();
			continue;
		}

		if (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GET) {
			unsigned char type = ASN_NULL;
			char *value = NULL;
			size_t len = 0;

			switch(table_info->colnum) {
				case 1: // Index
					type = ASN_UNSIGNED;
					value = (char *)&r->uid;
					len = sizeof(r->uid);
					break;

				case 2: { // Bytes
					type = ASN_COUNTER64;
					uint64_t v64 = perf_item_val_get_raw(r->perf_bytes);
					struct counter64 vc64;
					vc64.high = v64 >> 32;
					vc64.low = v64 & 0xFFFFFFFF;
					value = (char *) &vc64;
					len = sizeof(struct counter64);
					break;
				}

				case 3: { // Packets
					type = ASN_COUNTER64;
					uint64_t v64 = perf_item_val_get_raw(r->perf_pkts);
					struct counter64 vc64;
					vc64.high = v64 >> 32;
					vc64.low = v64 & 0xFFFFFFFF;
					value = (char *) &vc64;
					len = sizeof(struct counter64);
					break;
				}

				case 4: // Uptime
					type = ASN_TIMETICKS;
					uint64_t v = perf_item_val_get_raw(r->perf_uptime);
					value = (char *) &v;
					len = sizeof(uint64_t);
					break;

			}

			if (reqinfo->mode == MODE_GETNEXT) {
				*(table_info->indexes->val.integer) = r->uid;
				netsnmp_table_build_result(reginfo, requests, table_info, type, (unsigned char *)value, len);

			} else if (reqinfo->mode == MODE_GET && var->type == ASN_NULL) {
				snmp_set_var_typed_value(var, type, (unsigned char*)value, len);
			}


		}

		main_config_rules_unlock();

		requests = requests->next;
	}

	return SNMP_ERR_NOERROR;

}
