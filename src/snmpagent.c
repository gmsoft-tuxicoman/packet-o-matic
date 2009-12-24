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
#include "snmpcmd_input.h"
#include "snmpcmd_rules.h"
#include "snmpcmd_target.h"

int snmpagent_init() {

	// Install the log handler
	netsnmp_log_handler *log_handler = malloc(sizeof(netsnmp_log_handler));
	memset(log_handler, 0, sizeof(netsnmp_log_handler));
	log_handler->handler = snmpagent_log_handler;
	log_handler->enabled = 1;
	log_handler->priority = LOG_DEBUG;

	if (!netsnmp_add_loghandler(log_handler)) {
		pom_log(POM_LOG_ERR "Unable to install the log handler");
		return POM_ERR;
	}
	

	// Make this a subagent
	if (netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_ROLE, 1) != SNMPERR_SUCCESS) {
		pom_log(POM_LOG_ERR "Unable to set subagent mode");
		return POM_ERR;
	}

	// Don't load any config file
	if (netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_LIB_DISABLE_CONFIG_LOAD, 1) != SNMPERR_SUCCESS) {
		pom_log(POM_LOG_ERR "Unable to prevent loading config files");
		return POM_ERR;
	}

	if (init_agent(PACKAGE_NAME) != SNMPERR_SUCCESS) {
		pom_log(POM_LOG_ERR "Unable to init the snmp agent");
		return POM_ERR;
	}


	if (snmpagent_init_oids() != POM_OK) {
		pom_log(POM_LOG_ERR "Error while initializing the oids");
		return POM_ERR;
	}

	init_snmp(PACKAGE_NAME);



	return POM_OK;
}

int snmpagent_init_oids() {

	oid base_oid[] = { 1, 3, 6, 1, 4, 1, 31355, 2, 1 };
	snmpcmd_core_init_oids(base_oid, OID_LENGTH(base_oid));
	snmpcmd_input_init_oids(base_oid, OID_LENGTH(base_oid));
	snmpcmd_rules_init_oids(base_oid, OID_LENGTH(base_oid));
	snmpcmd_target_init_oids(base_oid, OID_LENGTH(base_oid));
	return POM_OK;

}

int snmpagent_process() {

	agent_check_and_process(1);

	return POM_OK;
}

int snmpagent_cleanup() {

//	shutdown_agent();
	snmp_shutdown(PACKAGE_NAME);

	return POM_OK;
}


int snmpagent_log_handler(netsnmp_log_handler* handler, int priority, const char *str) {

	char *ln = strrchr(str, '\n');
	if (ln)
		*ln = 0;

	pom_log(POM_LOG_INFO "%s", str);
	return 1; 

}
