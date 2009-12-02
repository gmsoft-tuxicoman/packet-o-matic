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
#include "snmpcmd_input.h"
#include "main.h"
#include "perf.h"

int snmpcmd_input_init_oids(oid *base_oid, int base_oid_len) {

	oid my_oid[MAX_OID_LEN];
	memcpy(my_oid, base_oid, base_oid_len * sizeof(oid));
	my_oid[base_oid_len] = 2;

	// Register type handler
	my_oid[base_oid_len + 1] = 1;
	netsnmp_handler_registration *input_type_handler = netsnmp_create_handler_registration("inputType", snmpcmd_input_type_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);
	netsnmp_register_instance(input_type_handler);

	// Register mode handler
	my_oid[base_oid_len + 1] = 2;
	netsnmp_handler_registration *input_mode_handler = netsnmp_create_handler_registration("inputMode", snmpcmd_input_mode_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);
	netsnmp_register_instance(input_mode_handler);

	// Register parameters handler
	my_oid[base_oid_len + 1] = 3;
	netsnmp_handler_registration *input_params_handler = netsnmp_create_handler_registration("inputParamTable", snmpcmd_input_param_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);

	if (!input_params_handler)
		return POM_ERR;

	netsnmp_table_registration_info *input_params_table_info = malloc(sizeof(netsnmp_table_registration_info));
	memset(input_params_table_info, 0, sizeof(netsnmp_table_registration_info));

	netsnmp_table_helper_add_indexes(input_params_table_info, ASN_INTEGER, 0);
	input_params_table_info->min_column = 1;
	input_params_table_info->max_column = 6;

	netsnmp_register_table(input_params_handler, input_params_table_info);

	// Register running handler
	my_oid[base_oid_len + 1] = 4;
	netsnmp_handler_registration *input_running_handler = netsnmp_create_handler_registration("inputStarted", snmpcmd_input_running_handler, my_oid, base_oid_len + 2, HANDLER_CAN_RWRITE);
	netsnmp_register_instance(input_running_handler);

	// Register perfs handler
	my_oid[base_oid_len + 1] = 5;

	// Register perfs bytes in handler
	my_oid[base_oid_len + 2] = 1;
	netsnmp_handler_registration *input_perf_bytes_in_handler = netsnmp_create_handler_registration("inputBytesIn", snmpcmd_input_perf_bytes_in_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(input_perf_bytes_in_handler);

	// Register perfs packets in handler
	my_oid[base_oid_len + 2] = 2;
	netsnmp_handler_registration *input_perf_pkts_in_handler = netsnmp_create_handler_registration("inputPktsIn", snmpcmd_input_perf_pkts_in_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(input_perf_pkts_in_handler);

	// Register perfs uptime in handler
	my_oid[base_oid_len + 2] = 3;
	netsnmp_handler_registration *input_perf_uptime_handler = netsnmp_create_handler_registration("inputRuntime", snmpcmd_input_perf_uptime_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(input_perf_uptime_handler);

	// Register perfs snaplen handler
	my_oid[base_oid_len + 2] = 4;
	netsnmp_handler_registration *input_perf_snaplen_handler = netsnmp_create_handler_registration("inputSnapLen", snmpcmd_input_perf_snaplen_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(input_perf_snaplen_handler);

	// Register perfs islive handler
	my_oid[base_oid_len + 2] = 5;
	netsnmp_handler_registration *input_perf_islive_handler = netsnmp_create_handler_registration("inputIsLive", snmpcmd_input_perf_islive_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RONLY);
	netsnmp_register_instance(input_perf_islive_handler);

	// Register input extra perf counter
	my_oid[base_oid_len + 2] = 6;
	netsnmp_handler_registration *input_perf_extra_counter_handler = netsnmp_create_handler_registration("inputPerfExtraCounterTable", snmpcmd_input_perf_extra_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RWRITE);

	if (!input_perf_extra_counter_handler)
		return POM_ERR;

	input_perf_extra_counter_handler->my_reg_void = (void*) perf_item_type_counter;
	netsnmp_table_registration_info *input_perf_extra_counter_table_info = malloc(sizeof(netsnmp_table_registration_info));
	memset(input_perf_extra_counter_table_info, 0, sizeof(netsnmp_table_registration_info));

	netsnmp_table_helper_add_indexes(input_perf_extra_counter_table_info, ASN_INTEGER, 0);
	input_perf_extra_counter_table_info->min_column = 1;
	input_perf_extra_counter_table_info->max_column = 4;

	netsnmp_register_table(input_perf_extra_counter_handler, input_perf_extra_counter_table_info);

	// Register input extra perf gauge
	my_oid[base_oid_len + 2] = 7;
	netsnmp_handler_registration *input_perf_extra_gauge_handler = netsnmp_create_handler_registration("inputPerfExtraGaugeTable", snmpcmd_input_perf_extra_handler, my_oid, base_oid_len + 3, HANDLER_CAN_RWRITE);

	if (!input_perf_extra_gauge_handler)
		return POM_ERR;

	input_perf_extra_gauge_handler->my_reg_void = (void*) perf_item_type_gauge;
	netsnmp_table_registration_info *input_perf_extra_gauge_table_info = malloc(sizeof(netsnmp_table_registration_info));
	memset(input_perf_extra_gauge_table_info, 0, sizeof(netsnmp_table_registration_info));

	netsnmp_table_helper_add_indexes(input_perf_extra_gauge_table_info, ASN_INTEGER, 0);
	input_perf_extra_gauge_table_info->min_column = 1;
	input_perf_extra_gauge_table_info->max_column = 4;

	netsnmp_register_table(input_perf_extra_gauge_handler, input_perf_extra_gauge_table_info);
	return POM_OK;

}


int snmpcmd_input_type_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	switch (reqinfo->mode) {
		case MODE_GET:
			if (rbuf->i && input_get_name(rbuf->i->type)) {
				char *type = input_get_name(rbuf->i->type);
				snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (unsigned char *)type, strlen(type));

			}
			break;

		case MODE_SET_RESERVE1:
			if (requests->requestvb->type != ASN_OCTET_STR)
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
			break;

		case MODE_SET_ACTION: {

			if (pthread_mutex_lock(&rbuf->mutex)) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
				pom_log(POM_LOG_ERR "Error while locking the buffer mutex");
				break;
			}

			char *new_type = (char*)requests->requestvb->val.string;
			if (rbuf->i) {
				if (rbuf->i->running) {
					pthread_mutex_unlock(&rbuf->mutex);
					netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
					pom_log(POM_LOG_DEBUG "Input is already running");
					break;
				}

				if (!strcmp(new_type, input_get_name(rbuf->i->type))) {
					pthread_mutex_unlock(&rbuf->mutex);
					netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
					pom_log(POM_LOG_DEBUG "Input type is already %s", new_type);
					break;
				}
			}
			
			input_lock(1);
			int input_type = input_register(new_type);
			if (input_type == POM_ERR) {
				input_unlock();
				pthread_mutex_unlock(&rbuf->mutex);
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
				pom_log(POM_LOG_DEBUG "Unable to register input of type %s", new_type);
				break;
			}

			struct input *i = input_alloc(input_type);
			input_unlock();

			if (!i) {
				pthread_mutex_unlock(&rbuf->mutex);
				pom_log(POM_LOG_DEBUG "Unable to allocate input of type %s", new_type);
				break;
			}

			if (rbuf->i)
				input_cleanup(rbuf->i);
			rbuf->i = i;
			main_config->input = i;

			if (pthread_mutex_unlock(&rbuf->mutex)) {
				pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex");
				break;
			}

			main_config->input_serial++;
			break;
		}

	}

	return SNMP_ERR_NOERROR;

}

int snmpcmd_input_mode_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	switch (reqinfo->mode) {
		case MODE_GET:
			if (rbuf->i) {
				char *mode = rbuf->i->mode->name;
				snmp_set_var_typed_value(requests->requestvb, ASN_OCTET_STR, (unsigned char *)mode, strlen(mode));

			}
			break;

		case MODE_SET_RESERVE1:
			if (requests->requestvb->type != ASN_OCTET_STR)
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
			break;

		case MODE_SET_ACTION: {
			
			char *new_mode = (char*)requests->requestvb->val.string;

			if (pthread_mutex_lock(&rbuf->mutex)) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
				pom_log(POM_LOG_ERR "Error while locking the buffer mutex");
			} else if (!rbuf->i) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
				pom_log(POM_LOG_DEBUG "Input not configured yet");
			} else if (rbuf->i->running) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
				pom_log(POM_LOG_DEBUG "Input is running. You need to stop it before doing any change");
			} else if (input_set_mode(rbuf->i, new_mode) != POM_OK) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
				pom_log(POM_LOG_DEBUG "No mode %s for this input");
			} else {
				main_config->input_serial++;
			}

			if (pthread_mutex_unlock(&rbuf->mutex)) {
				pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex");
			}

			break;
		}
		
	}
	return SNMP_ERR_NOERROR;
}

int snmpcmd_input_param_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {



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

		if (pthread_mutex_lock(&rbuf->mutex)) {
			netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
			pom_log(POM_LOG_ERR "Error while locking the buffer mutex");
			requests = requests->next;
			continue;
		}

		struct input_param *p = NULL;
		if (rbuf->i) {
			int i;
			p = rbuf->i->mode->params;
			for (i = 1; p && i < param_id; i++)
				p = p->next;
		}

		// Go to the next column
		if (!p && rbuf->i && reqinfo->mode == MODE_GETNEXT) {
			table_info->colnum++;
			param_id = 1;
			p = rbuf->i->mode->params;
		}

		if (!p) {
			pthread_mutex_unlock(&rbuf->mutex);
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
			if (table_info->colnum != 3) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
			} else if (rbuf->i->running) {
				pthread_mutex_unlock(&rbuf->mutex);
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
				pom_log(POM_LOG_DEBUG "Input is running. You need to stop it before doing any change");
			} else if (ptype_parse_val(p->value, new_val) != POM_OK) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
			} else {
				main_config->input_serial++;
			}
		}

		if (pthread_mutex_unlock(&rbuf->mutex)) {
			netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
			pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex");
		}

		requests = requests->next;

	}
	return SNMP_ERR_NOERROR;
}

int snmpcmd_input_running_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	switch (reqinfo->mode) {
		case MODE_GET:
			if (rbuf->i) {
				int running = 1;
				if (!rbuf->i->running)
					running = 2;
				snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, (unsigned char *)&running, sizeof(running));

			}
			break;

		case MODE_SET_RESERVE1:
			if (requests->requestvb->type != ASN_INTEGER)
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
			break;

		case MODE_SET_ACTION: {
			
			int run = *requests->requestvb->val.integer;
			if (run != 1 && run != 2) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
				break;
			}
				
			if (!rbuf->i) {
				netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
				pom_log(POM_LOG_DEBUG "Input not configured yet");
			} else {
				if (run == 1) {
					if (rbuf->i->running) {
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
						pom_log(POM_LOG_DEBUG "Input already running");
					} else {
						if (start_input(rbuf) != POM_OK) {
							netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
							pom_log(POM_LOG_ERR "Error while starting input");
						} else {
							main_config->input_serial++;
						}
					}
				} else if (run == 2) {
					if (!rbuf->i->running) {
						netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
						pom_log(POM_LOG_DEBUG "Input already stopped");
					} else {
						if (stop_input(rbuf) != POM_OK) {
							netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
							pom_log(POM_LOG_ERR "Error while stopping input");
						} else {
							main_config->input_serial++;
						}
					}
				} else {
					netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGVALUE);
				}
			}


			break;
		}
		
	}
	return SNMP_ERR_NOERROR;
}

int snmpcmd_input_perf_bytes_in_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET && rbuf->i) {
		uint64_t value = perf_item_val_get_raw(rbuf->i->perf_bytes_in);
		struct counter64 v;
		v.high = value >> 32;
		v.low = value & 0xFFFFFFFF;
		snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64, (unsigned char*) &v, sizeof(v));
	}
	return SNMP_ERR_NOERROR;
}

int snmpcmd_input_perf_pkts_in_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET && rbuf->i) {
		uint64_t value = perf_item_val_get_raw(rbuf->i->perf_pkts_in);
		struct counter64 v;
		v.high = value >> 32;
		v.low = value & 0xFFFFFFFF;
		snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER64, (unsigned char*) &v, sizeof(v));
	}
	return SNMP_ERR_NOERROR;
}

int snmpcmd_input_perf_uptime_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET && rbuf->i) {
		uint64_t value = perf_item_val_get_raw(rbuf->i->perf_uptime);
		snmp_set_var_typed_value(requests->requestvb, ASN_TIMETICKS, (unsigned char*) &value, sizeof(value));
	}
	return SNMP_ERR_NOERROR;
}

int snmpcmd_input_perf_snaplen_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET && rbuf->i && rbuf->i->running) {
		uint32_t snaplen = rbuf->ic.snaplen;
		snmp_set_var_typed_value(requests->requestvb, ASN_GAUGE, (unsigned char*) &snaplen, sizeof(snaplen));
	}
	return SNMP_ERR_NOERROR;
}

int snmpcmd_input_perf_islive_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	if (reqinfo->mode == MODE_GET && rbuf->i && rbuf->i->running) {
		int is_live = rbuf->ic.is_live;
		if (!is_live)
			is_live = 2;
		snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER, (unsigned char*) &is_live, sizeof(is_live));
	}
	return SNMP_ERR_NOERROR;
}

static struct perf_item *snmpcmd_input_perf_item_getnext(struct perf_item *itm, enum perf_item_type type) {
	
	while (itm && (itm->type != type || itm == rbuf->i->perf_pkts_in || itm == rbuf->i->perf_bytes_in || itm == rbuf->i->perf_uptime))
		itm = itm->next;
	return itm;

}

int snmpcmd_input_perf_extra_handler(netsnmp_mib_handler *handler, netsnmp_handler_registration *reginfo, netsnmp_agent_request_info *reqinfo, netsnmp_request_info *requests) {

	enum perf_item_type type = (enum perf_item_type)reginfo->my_reg_void;

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

		// We must have an input
		if (!rbuf->i) {
			requests = requests->next;
			continue;
		}

		// Find the right perf item if any

		int item_id = *(table_info->indexes->val.integer);
		if (reqinfo->mode == MODE_GETNEXT)
			item_id++;


		struct perf_item *itm = snmpcmd_input_perf_item_getnext(rbuf->i->perfs->items, type);
		int i;
		for (i = 1; itm && i < item_id; i++) {
			itm = snmpcmd_input_perf_item_getnext(itm->next, type);
		}

		// Go to the next column
		if (!itm && reqinfo->mode == MODE_GETNEXT) {
			table_info->colnum++;
			item_id = 1;
			itm = snmpcmd_input_perf_item_getnext(rbuf->i->perfs->items, type);
		}

		if (!itm) {
			requests = requests->next;
			continue;
		}

	
		if (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GET) {
			unsigned char res_type = ASN_NULL;
			char *value = NULL;
			size_t len = 0;
			
			switch (table_info->colnum) {
				case 1: // Index
					res_type = ASN_UNSIGNED;
					value = (char *)&item_id;
					len = sizeof(item_id);
					break;
				case 2: // Item name
					res_type = ASN_OCTET_STR;
					value = itm->name;
					len = strlen(value);
					break;
				case 3: { // Item value
					if (type == perf_item_type_counter) {
						uint64_t v64 = perf_item_val_get_raw(itm);
						struct counter64 vc64;
						vc64.high = v64 >> 32;
						vc64.low = v64 & 0xFFFFFFFF;
						value = (char *) (&vc64);
						res_type = ASN_COUNTER64;
						len = sizeof(struct counter64);
					} else if (type == perf_item_type_gauge) {
						int32_t v = perf_item_val_get_raw(itm);
						value = (char *)&v;
						res_type = ASN_GAUGE;
						len = sizeof(int32_t);
					}
					break;
				}
				case 4: // Item description
					res_type = ASN_OCTET_STR;
					value = itm->descr;
					len = strlen(value);
					break;
			}

			if (value) {

				if (reqinfo->mode == MODE_GETNEXT) {
					*(table_info->indexes->val.integer) = item_id;
					netsnmp_table_build_result(reginfo, requests, table_info, res_type, (unsigned char *)value, len);

				} else if (reqinfo->mode == MODE_GET && var->type == ASN_NULL) {
					snmp_set_var_typed_value(var, res_type, (unsigned char *)value, len);
				}
			}

		}

		requests = requests->next;
	}
	return SNMP_ERR_NOERROR;
}
