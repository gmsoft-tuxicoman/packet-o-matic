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
#include "snmpcmd_core.h"
#include "main.h"
#include "perf.h"
#include "version.h"

int snmpcmd_core_init_oids(oid *base_oid, int base_oid_len) {

	oid my_oid[MAX_OID_LEN];
	memcpy(my_oid, base_oid, base_oid_len * sizeof(oid));
	my_oid[base_oid_len] = 1;

	// Register running handler
	my_oid[base_oid_len + 1] = 1;
	netsnmp_handler_registration *core_running_handler = netsnmp_create_handler_registration("coreRunning", snmpcmd_core_running_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);
	netsnmp_register_instance(core_running_handler);

	// Register debug level handler
	my_oid[base_oid_len + 1] = 2;
	netsnmp_handler_registration *core_debug_level_handler = netsnmp_create_handler_registration("coreDebugLevel", snmpcmd_core_debug_level_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);
	netsnmp_register_instance(core_debug_level_handler);

	// Register parameters handler
	my_oid[base_oid_len + 1] = 3;
	netsnmp_handler_registration *core_params_handler = netsnmp_create_handler_registration("coreParamTable", snmpcmd_core_param_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);

	if (!core_params_handler)
		return POM_ERR;

	netsnmp_table_registration_info *core_params_table_info = malloc(sizeof(netsnmp_table_registration_info));
	memset(core_params_table_info, 0, sizeof(netsnmp_table_registration_info));

	netsnmp_table_helper_add_indexes(core_params_table_info, ASN_INTEGER, 0);
	core_params_table_info->min_column = 1;
	core_params_table_info->max_column = 6;

	netsnmp_register_table(core_params_handler, core_params_table_info);

	// Register perf handler
	my_oid[base_oid_len + 1] = 4;

	// Register perf core version handler
	my_oid[base_oid_len + 2] = 1;
	netsnmp_handler_registration *core_perf_version_handler = netsnmp_create_handler_registration("corePerfVersion", snmpcmd_core_perf_version_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(core_perf_version_handler);

	// Register perf core uptime handler
	my_oid[base_oid_len + 2] = 2;
	netsnmp_handler_registration *core_perf_uptime_handler = netsnmp_create_handler_registration("corePerfRuntime", snmpcmd_core_perf_uptime_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(core_perf_uptime_handler);

	// Register perf ring buffer pkts handler
	my_oid[base_oid_len + 2] = 3;
	netsnmp_handler_registration *core_perf_ringbuff_pkts_handler = netsnmp_create_handler_registration("corePerfRingBuffPkts", snmpcmd_core_perf_ringbuff_pkts_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(core_perf_ringbuff_pkts_handler);

	// Register perf ring buffer total pkts handler
	my_oid[base_oid_len + 2] = 4;
	netsnmp_handler_registration *core_perf_ringbuff_totpkts_handler = netsnmp_create_handler_registration("corePerfRingBuffTotPkts", snmpcmd_core_perf_ringbuff_totpkts_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(core_perf_ringbuff_totpkts_handler);

	// Register perf ring buffer dropped pkts handler
	my_oid[base_oid_len + 2] = 5;
	netsnmp_handler_registration *core_perf_ringbuff_droppedpkts_handler = netsnmp_create_handler_registration("corePerfRingBuffDroppedPkts", snmpcmd_core_perf_ringbuff_droppedpkts_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(core_perf_ringbuff_droppedpkts_handler);

	// Register perf ring buffer overflow handler
	my_oid[base_oid_len + 2] = 6;
	netsnmp_handler_registration *core_perf_ringbuff_overflow_handler = netsnmp_create_handler_registration("corePerfRingBuffOverflow", snmpcmd_core_perf_ringbuff_overflow_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(core_perf_ringbuff_overflow_handler);

	return POM_OK;

}


int snmpcmd_core_running_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	switch (reqinfo->mode) {
		case MODE_GET: {
			int running = 1;
			snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, (unsigned char *)&running, sizeof(running));
			break;
		}
			
		case MODE_SET_RESERVE1:
			if (requests->requestvb->type != ASN_INTEGER)
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
			break;

		case MODE_SET_ACTION: {
			int run = *requests->requestvb->val.integer;
			if (run == 2) {
				halt();
			} else {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
			}
			break;
		}
	}

	return SNMP_ERR_NOERROR;
}

int snmpcmd_core_debug_level_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	switch (reqinfo->mode) {
		case MODE_GET: {
			snmp_set_var_typed_value(requests->requestvb, ASN_UNSIGNED, (unsigned char *)&console_debug_level, sizeof(console_debug_level));
			break;
		}
			
		case MODE_SET_RESERVE1:
			if (requests->requestvb->type != ASN_UNSIGNED)
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
			break;

		case MODE_SET_ACTION: {
			unsigned int new_level = *requests->requestvb->val.integer;
			if (new_level > *POM_LOG_TSHOOT) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
			} else {
				console_debug_level = new_level;
			}
			break;
		}
	}

	return SNMP_ERR_NOERROR;

}

int snmpcmd_core_param_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

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
			if (table_info->colnum != 3) // Set only allowed on values
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
			else if (requests->requestvb->type != ASN_OCTET_STR)
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
			requests = requests->next;
			continue;
		}
	
		// Get rid of useless modes
		if (reqinfo->mode != MODE_GETNEXT && reqinfo->mode != MODE_GET && reqinfo->mode != MODE_SET_ACTION) {
			requests = requests->next;
			continue;
		}

		// Find the right parameter
		int param_id = *(table_info->indexes->val.integer);
		if (reqinfo->mode == MODE_GETNEXT)
			param_id++;

		struct core_param *p = core_param_get_head();
		int i;
		for (i = 1; p && i < param_id; i++)
			p = p->next;

		// Go to the next column
		if (!p && reqinfo->mode == MODE_GETNEXT) {
			table_info->colnum++;
			param_id = 1;
			p = core_param_get_head();
		}

		if (!p) {
			requests = requests->next;
			continue;
		}

	
		if (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GET) {
			unsigned char type = ASN_NULL;
			char *value = NULL;
			size_t len = 0;
			
			switch (table_info->colnum) {
				case 1: // Index
					type = ASN_UNSIGNED;
					value = (char *)&param_id;
					len = sizeof(param_id);
					break;
				case 2: // Param name
					type = ASN_OCTET_STR;
					value = p->name;
					len = strlen(value);
					break;
				case 3: // Param value
					type = ASN_OCTET_STR;
					value = ptype_print_val_alloc(p->value);
					len = strlen(value);
					break;
				case 4: // Param unit
					type = ASN_OCTET_STR;
					value = p->value->unit;
					len = strlen(value);
					break;
				case 5: // Param type
					type = ASN_OCTET_STR;
					value = ptype_get_name(p->value->type);
					len = strlen(value);
					break;

				case 6: // Param description
					type = ASN_OCTET_STR;
					value = p->descr;
					len = strlen(value);
					break;
			}

			if (value) {

				if (reqinfo->mode == MODE_GETNEXT) {
					*(table_info->indexes->val.integer) = param_id;
					netsnmp_table_build_result(reginfo, requests, table_info, type, (unsigned char *)value, len);

				} else if (reqinfo->mode == MODE_GET && var->type == ASN_NULL) {
					snmp_set_var_typed_value(var, type, (unsigned char *)value, len);
				}
			}

			if (table_info->colnum == 3) // value was allocated earlier
				free(value);


		} else if (reqinfo->mode == MODE_SET_ACTION) {
			char *new_val = (char*)requests->requestvb->val.string;
			char err[255];
			if (core_set_param_value(p->name, new_val, err, sizeof(err) - 1) != POM_OK) {
				pom_log(POM_LOG_DEBUG "Error while setting core parameter name : %s", err);
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
			} 
		}

		requests = requests->next;

	}
	return SNMP_ERR_NOERROR;
}

int snmpcmd_core_perf_version_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET)
		snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (unsigned char *)POM_VERSION, strlen(POM_VERSION));
			
	return SNMP_ERR_NOERROR;
}

int snmpcmd_core_perf_uptime_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET) {
		uint64_t value = perf_item_val_get_raw(core_perf_uptime);
		snmp_set_var_typed_value(requests->requestvb, ASN_TIMETICKS, (unsigned char *)&value, sizeof(value));
	}
			
	return SNMP_ERR_NOERROR;
}

int snmpcmd_core_perf_ringbuff_pkts_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET) {
		unsigned int value = rbuf->usage;
		snmp_set_var_typed_value(requests->requestvb, ASN_GAUGE, (unsigned char *)&value, sizeof(unsigned int));
	}
			
	return SNMP_ERR_NOERROR;
}

int snmpcmd_core_perf_ringbuff_totpkts_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET) {
		uint64_t value = perf_item_val_get_raw(rbuf->perf_total_packets);
		struct counter64 v;
		v.high = value >> 32;
		v.low = value & 0xFFFFFFFF;
		snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64, (unsigned char *)&v, sizeof(v));
	}
			
	return SNMP_ERR_NOERROR;
}

int snmpcmd_core_perf_ringbuff_droppedpkts_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET) {
		uint64_t value = perf_item_val_get_raw(rbuf->perf_dropped_packets);
		struct counter64 v;
		v.high = value >> 32;
		v.low = value & 0xFFFFFFFF;
		snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64, (unsigned char *)&v, sizeof(v));
	}
			
	return SNMP_ERR_NOERROR;
}

int snmpcmd_core_perf_ringbuff_overflow_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET) {
		uint64_t value = perf_item_val_get_raw(rbuf->perf_overflow);
		struct counter64 v;
		v.high = value >> 32;
		v.low = value & 0xFFFFFFFF;
		snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64, (unsigned char *)&v, sizeof(v));
	}
			
	return SNMP_ERR_NOERROR;
}
