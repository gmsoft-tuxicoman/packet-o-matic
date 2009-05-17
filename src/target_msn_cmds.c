/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2008-2009 Guy Martin <gmsoft@tuxicoman.be>
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


#include "target_msn_cmds.h"
#include "target_msn_session.h"

unsigned int msn_cmd_tokenize(char *cmd, char *tokens[]) {

	unsigned int tok_num = 0;
	char *str, *tok, *saveptr = NULL;
	for (str = cmd; ; str = NULL) {
		tok = strtok_r(str, " ", &saveptr);
		if (!tok)
			break;
		tokens[tok_num] = tok;
		tok_num++;
	}
	return tok_num;
}

struct target_msg_msn *msn_cmd_alloc_msg(unsigned int size, enum msn_payload_type type) {

	struct target_msg_msn *my_msg = malloc(sizeof(struct target_msg_msn));
	memset(my_msg, 0, sizeof(struct target_msg_msn));
	my_msg->tot_len = size;
	my_msg->cur_len = 0;
	my_msg->payload_type = type;

	return my_msg;
}

// Protocol version negociation
int target_msn_handler_ver(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : VER TrID ver1 ver2 ... 
	// server : VER TrID ver


	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	char *version = tokens[2];

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse VER command");
		return POM_OK;
	}

	if (tok_num > 3) { // It was a client with multiple version
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		version = NULL;
	}

	if (version) {
		struct target_session_priv_msn *sess = cp->session;
		if (sscanf(version, "MSNP%u", &sess->version) != 1) {
			pom_log(POM_LOG_DEBUG "Warning, cannot parse MSN protocol version : %s", version);
			sess->version = 0;
			return POM_OK;
		}
		pom_log(POM_LOG_TSHOOT "Protocol version is %u" , sess->version);
	}
	return POM_OK;
}

// Client version update
int target_msn_handler_cvr(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : CVR TrID locale_id os_type os_version arch client_name client_version MSMSGS account
	// (locale_id is in hexa -> starts by 0x...)
	// server : CVR TrID recommended_version recommended_version server_version? url_dl_client url_more_info

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse CVR command");
		return POM_OK;
	}

	if (!memcmp(tokens[2], "0x", strlen("0x"))) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		if (tok_num > 9)
			target_msn_session_found_account(t, cp, tokens[9]);
	} else {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	}

	return POM_OK;
}

// Authentication
int target_msn_handler_usr(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// MSNP 8->14 :
	// client : USR TrID TWN I account
	// server : USR TrID TWN S auth_string
	// client : USR TrID TWN S ticket
	// server : USR TrID OK account friendly_name verified 0
	
	// MSNP15
	// client : USR TrID SSO I account
	// server : USR TrID SSO S policy base64_nonce
	// client : USR Trid SSO S base64_response
	// server : USR TrID OK account verified 0

	// MSNP18
	// client : USTR TrID SHA A credentials
	
	// Switchboard server :
	// client : USR TrID account ticket
	// server : USR TrID OK account friendly_name

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 4) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse USR command");
		return POM_OK;
	}

	// Let's see what kind of message we have
	char *at = strchr(tokens[2], '@');
	if (at) { // switchboard from client

		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		target_msn_session_found_account(t, cp, tokens[2]);

	} else if (!strcmp(tokens[2], "OK")) { // server replies OK

		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		target_msn_session_found_account(t, cp, tokens[3]);
		if (*tokens[4] != '0' && *tokens[4] != '1')
			target_msn_session_found_friendly_name(cp, tokens[4], &f->tv);

	} else if (!strcmp(tokens[2], "TWN") || !memcmp(tokens[2], "SSO", 3)) {

		// TWN or SSO
		if (*tokens[3] == 'I') { // client initial message
			if (tok_num >= 5) {
				target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
				target_msn_session_found_account(t, cp, tokens[4]);
			}

		}
	} else if (!strcmp(tokens[2], "SHA")) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
	} else {
		pom_log(POM_LOG_DEBUG "Unhandled USR message with %s parameter", tokens[2]);
		return POM_OK;
	}

	return POM_OK;
}

// Transfer to another server
int target_msn_handler_xfr(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : XFR TrID SB|NS
	// server : XFR TrID SB|NS new_addr:port CKI auth_string
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse XFR command");
		return POM_OK;
	}

	if (!memcmp("NS", tokens[2], 2) && !memcmp("SB", tokens[2], 2)) {
		pom_log(POM_LOG_DEBUG "Invalid XFR message : %s", tokens[2]);
		return POM_OK;
	} 

	if (tok_num >= 4) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		struct target_conntrack_priv_msn *new_cp = target_msn_conntrack_priv_fork(t, cp, f);
		target_msn_add_expectation(t, new_cp, f, tokens[3]);

	} else {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
	}


	return POM_OK;
}

// Message
int target_msn_handler_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : MSG TrID ack_type length
	// server : MSG account friendly_name length
	// server : MSG Hotmail Hotmail length

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 4) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse MSG command");
		return POM_OK;
	}

	unsigned int size = 0;
	if (sscanf(tokens[3], "%u", &size) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid size provided : %s", tokens[3]);
		return POM_OK;
	}

	unsigned int trid;
	struct target_connection_party_msn *from = NULL;

	if (strchr(tokens[1], '@') != NULL) { // We found an account name -> msg from server
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		from = target_msn_session_found_party(cp, tokens[1], NULL);
	} else if (sscanf(tokens[1], "%u", &trid) == 1) { // We found a TrID -> msg from client
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
	} else { // Not an account nor TrID -> system message from server
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	}


	if (size > 0) {
		
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(size, msn_payload_type_msg);

		if (from) {
			struct target_msg_msn *msg = cp->msg[cp->curdir];
			msg->from = from->buddy;
		}
	}

	return POM_OK;
}

// Getting/setting personal details
int target_msn_handler_prp(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// MSNP 8->10
	// client : PRP number_type(3alpha) number_value
	
	// MSNP11->above
	// client/server : PRP TrID MFN friendly_name

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse MSG command");
		return POM_OK;
	}

	unsigned int trid = 0;
	if (tok_num == 4 && sscanf(tokens[1], "%u", &trid) == 1) {
		// MSNP11 and above
		if (!strcmp(tokens[2], "MFN")) {
			pom_log(POM_LOG_TSHOOT "My friendly name : \"%s\"", tokens[3]);
			target_msn_session_found_friendly_name(cp, tokens[3], &f->tv);
		} else {
			pom_log(POM_LOG_DEBUG "Unknown PRP type : %s", tokens[2]);
		}

	} else {

		if (!strcmp(tokens[1], "PHH")) {
			pom_log(POM_LOG_TSHOOT "Home phome number : %s", tokens[2]);
		} else if (!strcmp(tokens[1], "PHW")) {
			pom_log(POM_LOG_TSHOOT "Work phome number : %s", tokens[2]);
		} else if (!strcmp(tokens[1], "PHM")) {
			pom_log(POM_LOG_TSHOOT "Mobile phome number : %s", tokens[2]);
		} else if (!strcmp(tokens[1], "MOB")) {
			pom_log(POM_LOG_TSHOOT "Can people call mobile device ? : %s", tokens[2]);
		} else if (!strcmp(tokens[1], "MBE")) {
			pom_log(POM_LOG_TSHOOT "Mobile device enabled ? : %s", tokens[2]);
		} else if (!strcmp(tokens[1], "WWE")) {
			pom_log(POM_LOG_TSHOOT "Direct paging ? : %s", tokens[2]);
		} else if (!strcmp(tokens[1], "MFN")) {
			pom_log(POM_LOG_TSHOOT "My friendly name : \"%s\"", tokens[2]);
			target_msn_session_found_friendly_name(cp, tokens[2], &f->tv);
		} else {
			pom_log(POM_LOG_DEBUG "Unknown PRP type : %s", tokens[1]);
		}
	}

	return POM_OK;
}


// List of group
int target_msn_handler_lsg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// doublecheck ?
	// client : LSG TrID
	// server : LSG TrID modification_id inc_id tot_group gid group_name 0
	

	// MSNP 11 and above
	// server : LSG group_name guid

	if (f->ce->direction != cp->server_dir) {
		pom_log(POM_LOG_TSHOOT "LSG not comming from server (or server dir unknown), ignoring.");
		return POM_OK;
	}

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 2) {
		pom_log(POM_LOG_DEBUG "LSG command imcomplete");
		return POM_OK;
	}
	
	// Old Syntax ?
	if (tok_num > 6) {
		// Allright, make sure that that's it
		int id;
		if (sscanf(tokens[5], "%u", &id) != 1) {
			pom_log(POM_LOG_DEBUG "LSG: Invalid group ID received");
			return POM_OK;
		}
		return target_msn_session_found_group(cp, tokens[6], tokens[5]);

	} else if (tok_num > 2) {
		// Could check the GUID but too lazy
		return target_msn_session_found_group(cp, tokens[1], tokens[2]);
	} else {
		// Only 1 arg -> from client
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
	}
	
	return POM_OK;
}


// List of contacts
int target_msn_handler_lst(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {
	
	// server : LST account friendly_name list_id group_list(optional)
	
	// MSNP 11 and above
	// server : LST N=account F=friendly_name(optional) C=guid list_id group_list(optional)
	
	if (f->ce->direction != cp->server_dir) {
		pom_log(POM_LOG_TSHOOT "LST not comming from server (or server dir unknown), ignoring.");
		return POM_OK;
	}

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 2) {
		pom_log(POM_LOG_DEBUG "LST command imcomplete");
		return POM_OK;
	}

	// Okay, so microsoft fscking SUX ! that's an assertion
	// Let's try to make sens of whatever the server will send
	// Stupid protocol has like 5 different syntax for the same command
	// Who the hell needs 15 different versions of a protocol ???
	// They are probably too st00pid to get it right

	int new_syntax = 0;
	if (!strcmp(tokens[1], "N=")) // New syntax alway give account prepended with N=
		new_syntax = 1;

	char *account = NULL, *nick = NULL, *group = NULL;
	if (new_syntax) {
		account = tokens[1] + 2;
		if (tok_num > 4)
			group = tokens[4]; // group can be null
		if (!strcmp(tokens[2], "F=")) {
			nick = tokens[2] + 2;
			if (tok_num > 5)
				group = tokens[5];
		}
	} else {
		account = tokens[1];
		nick = tokens[2];
		if (tok_num > 4)
			group = tokens[4];
	}
	
	if (nick && account) {
		pom_log(POM_LOG_TSHOOT "Account in the list : \"%s\" (%s)", nick, account);
		target_msn_session_found_buddy(cp, account, nick, group);
	}

	return POM_OK;
}


// Change status
int target_msn_handler_chg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client/server : CHG TrID status capabilities(optional) object_descriptor(optional)

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 2) {
		pom_log(POM_LOG_DEBUG "CHG command imcomplete");
		return POM_OK;
	}

	struct target_session_priv_msn *sess = cp->session;

	enum msn_status_type new_status = msn_status_unknown;

	char *status_msg = NULL;
	if (!strcmp("NLN", tokens[2])) {
		status_msg = "Available";
		new_status = msn_status_available;
	} else if (!strcmp("BSY", tokens[2])) {
		status_msg = "Busy";
		new_status = msn_status_busy;
	} else if (!strcmp("IDL", tokens[2])) {
		status_msg = "Idle";
		new_status = msn_status_idle;
	} else if (!strcmp("BRB", tokens[2])) {
		status_msg = "Be right back";
		new_status = msn_status_brb;
	} else if (!strcmp("AWY", tokens[2])) {
		status_msg = "Away";
		new_status = msn_status_away;
	} else if (!strcmp("PHN", tokens[2])) {
		status_msg = "On the phone";
		new_status = msn_status_phone;
	} else if (!strcmp("LUN", tokens[2])) {
		status_msg = "Out for lunch";
		new_status = msn_status_lunch;
	} else if (!strcmp("HDN", tokens[2])) {
		status_msg = "Hidden";
		new_status = msn_status_hidden;
	} else {
		status_msg = "Unknown";
	}


	if (sess->user.status != new_status) {
		pom_log(POM_LOG_TSHOOT "Status changed : %s", status_msg);
		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.buff = status_msg;
		evt.from = &sess->user;
		evt.type = msn_evt_status_change;
		
		sess->user.status = new_status;

		target_msn_session_event(cp, &evt);
	}


	return POM_OK;
}

// PING
int target_msn_handler_png(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	pom_log(POM_LOG_TSHOOT "PING from client");
	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
	return POM_OK;
}

// PONG
int target_msn_handler_qng(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	pom_log(POM_LOG_TSHOOT "PONG from server");
	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	return POM_OK;
}

// Receive personal message (status)
int target_msn_handler_ubx(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// MSNP 11
	// server : UBX account length
	
	/// MSNP 13
	// server : UBX account (Length) // really ?
	
	// MSNP 14->15
	// server : UBX account networkid length
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	unsigned int length = 0;
	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "UBX command incomplete");
		return POM_OK;
	}

	int len_token = 2;
	if (tok_num > 3)
		len_token = 3;

	if (sscanf(tokens[len_token], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid length received : %s", tokens[len_token]);
		return POM_OK;
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	// MSNP 17->18 prefix the account with X:
	char *account = strchr(tokens[1], ':');
	if (account)
		account++;
	else
		account = tokens[1];

	struct target_buddy_msn *buddy = target_msn_session_found_buddy(cp, account, NULL, NULL);

	if (length > 0) {
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_status_msg);
		cp->msg[cp->curdir]->from = buddy;
	}

	return POM_OK;
}


// Receiving file transfert 
int target_msn_handler_ubn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// MSNP 13->15
	// client : UBN account type length
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	unsigned int length = 0;
	if (tok_num < 4) {
		pom_log(POM_LOG_DEBUG "UBN command incomplete");
		return POM_OK;
	}

	if (sscanf(tokens[3], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid length received : %s", tokens[3]);
		return POM_OK;
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	if (length > 0)
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);

	return POM_OK;
}


// Invite user to switchboard
int target_msn_handler_cal(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : CAL TrID account
	// server : CAL TrID RINGING session_id

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "CAL command incomplete");
		return POM_OK;
	}


	if (!strcmp("RINGING", tokens[2])) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		pom_log(POM_LOG_TSHOOT "User accepted to join");
		return POM_OK;

	}

	char *at = strchr(tokens[2], '@');
	if (at) {
		target_msn_session_found_party(cp, tokens[2], NULL);
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
	} else {
		pom_log(POM_LOG_DEBUG "Unhandled CAL message");
	}

	return POM_OK;
}

// User joined switchboard
int target_msn_handler_joi(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : JOI account friendly_name

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "JOI command incomplete");
		return POM_OK;
	}

	pom_log(POM_LOG_TSHOOT "JOI: User \"%s\" (%s) has joined the conversation", tokens[2], tokens[1]);
	struct target_connection_party_msn *party = NULL;
	party = target_msn_session_found_party(cp, tokens[1], tokens[2]);

	if (party) {
		party->joined = 1;

		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.from = party->buddy;
		evt.type = msn_evt_buddy_join;

		target_msn_session_event(cp, &evt);
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	return POM_OK;
}

// List of parties in the conversation
int target_msn_handler_iro(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : IRO TrID roster rostercount account friendly_name

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 6) {
		pom_log(POM_LOG_DEBUG "IRO command incomplete");
		return POM_OK;
	}

	pom_log(POM_LOG_TSHOOT "IRO: User \"%s\" (%s) has joined the conversation", tokens[5], tokens[4]);
	struct target_connection_party_msn *party = NULL;
	party = target_msn_session_found_party(cp, tokens[4], tokens[5]);

	if (party) {
		party->joined = 1;

		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.from = party->buddy;
		evt.type = msn_evt_buddy_join;

		target_msn_session_event(cp, &evt);
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	return POM_OK;
}

// Verify identity to switchboard
int target_msn_handler_ans(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : ANS TrID account ticket session_id
	// server : ANS TrID OK

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "ANS command incomplete");
		return POM_OK;
	}


	if (!strcmp(tokens[2], "OK")) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		return POM_OK;
	} else {
		char *at = strchr(tokens[2], '@'); // Basic verification
		if (at) {
			target_msn_session_found_account(t, cp, tokens[2]);
			target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
			return POM_OK;
		}
	}

	pom_log(POM_LOG_DEBUG "Unhandled ASN message : %s", tokens[2]);

	return POM_OK;
}

// Ack of MSG
int target_msn_handler_ack(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : ACK TrID

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	return POM_OK;
}

// MSG wasn't received
int target_msn_handler_nak(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : NAK TrID

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	return POM_OK;
}

// Contact leaves conversation
int target_msn_handler_bye(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : BYE account reason_id(optional)

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 2) {
		pom_log(POM_LOG_DEBUG "BYE command incomplete");
		return POM_OK;
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	char *at = strchr(tokens[1], '@');
	if (at) {
		char *sc = strchr(tokens[1], ';');
		if (sc)
			*sc = 0;

		struct target_connection_party_msn *tmp = cp->parts;
		while (tmp) {
			if (!strcmp(tmp->buddy->account, tokens[1])) {
				break;
			}
			tmp = tmp->next;
		}
		if (!tmp) {
			pom_log(POM_LOG_DEBUG "BYE: User %s not found in the list", tokens[1]);
		} else {
			pom_log(POM_LOG_TSHOOT "BYE: User %s left the conversation", tokens[1]);
			tmp->joined = 0;

			struct target_event_msn evt;
			memset(&evt, 0, sizeof(struct target_event_msn));
			memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
			evt.from = tmp->buddy;
			evt.type = msn_evt_buddy_leave;

			target_msn_session_event(cp, &evt);
		}

	} else {
		pom_log(POM_LOG_DEBUG "Invalid account name in BYE command : %s", tokens[1]);
	}


	return POM_OK;
}

// Notification
int target_msn_handler_not(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : NOT length

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 2) {
		pom_log(POM_LOG_DEBUG "NOT command incomplete");
		return POM_OK;
	}
	
	unsigned int length = 0;
	if (sscanf(tokens[1], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid length received : %s", tokens[1]);
		return POM_OK;
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	if (length > 0)
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);

	return POM_OK;
}

// Someone wants to chat with you
int target_msn_handler_rng(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : RNG session_id switchboard_address auth_type ticket account friendly_name

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 7) {
		pom_log(POM_LOG_DEBUG "RNG command incomplete");
		return POM_OK;
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	if (strcmp("CKI", tokens[3])) {
		pom_log(POM_LOG_DEBUG "Invalid RNG message : %s", tokens[3]);
		return POM_OK;
	}

	struct target_connection_party_msn *party = NULL;
	party = target_msn_session_found_party(cp, tokens[5], tokens[6]);


	struct target_conntrack_priv_msn *new_cp = target_msn_conntrack_priv_fork(t, cp, f);
	target_msn_add_expectation(t, new_cp, f, tokens[2]);

	return POM_OK;
}

// User is disconnecting
int target_msn_handler_out(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : OUT
	// server : OUT OTH|SSD
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	char *account = "Unknown";
	struct target_session_priv_msn *sess = cp->session;
	if (sess->user.account)
		account = sess->user.account;

	struct target_event_msn evt;
	memset(&evt, 0, sizeof(struct target_event_msn));
	memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
	evt.from = &sess->user;

	if (cp->fd != -1) // let's try to see if it's a NS or SB 
		evt.type = msn_evt_buddy_leave;
	else
		evt.type = msn_evt_user_disconnect;

	if (tok_num > 1) {
		char *msg = "Unknown reason";
		if (!strcmp(tokens[1], "OTH"))
			msg = "Logged in from another location";

		if (!strcmp(tokens[1], "SSD"))
			msg = "Server shutting down";

		pom_log(POM_LOG_TSHOOT "OUT : User %s disconnected by server : %s", account, msg);
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		evt.buff = msg;

	} else {
		char *msg = "User closed the conversation";
		if (cp->fd == -1)
			msg = "Signed out";

		pom_log(POM_LOG_TSHOOT "OUT: %s", msg);
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		evt.buff = msg;
	}

	target_msn_session_event(cp, &evt);

	return POM_OK;
}

// Change of presence
int target_msn_handler_nln(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	
	// server : NLN status account friendly_name capabilities msn_obj(optional)
	
	// MSNP 14 -> above
	// server : NLN status account network_id friendly_name capabilities msn_obj(optional)
	

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 5) {
		pom_log(POM_LOG_DEBUG "NLN command incomplete");
		return POM_OK;
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	struct target_buddy_msn *buddy = NULL;
	char *at = strchr(tokens[2], '@'); // Basic verification
	if (at) {
		// MSNP 18->above add 1: in front of the account name
		char *account = strchr(tokens[2], ':');
		if (account)
			account++;
		else
			account = tokens[2];

		unsigned int trid = 0;
		char *friendly = tokens[3];
		if (sscanf(friendly, "%u", &trid) == 1) {
			// MSNP 14->above syntax
			friendly = tokens[4];
		}

		buddy = target_msn_session_found_buddy(cp, account, friendly, NULL);
	} else {
		pom_log(POM_LOG_DEBUG "Warning, invalid NLN message : %s", tokens[3]);
		return POM_OK;
	}

	int new_status = msn_status_unknown;
	char *status_msg = NULL;
	if (!strcmp("NLN", tokens[1])) {
		status_msg = "Available";
		new_status = msn_status_available;
	} else if (!strcmp("BSY", tokens[1])) {
		status_msg = "Busy";
		new_status = msn_status_busy;
	} else if (!strcmp("IDL", tokens[1])) {
		status_msg = "Idle";
		new_status = msn_status_idle;
	} else if (!strcmp("BRB", tokens[1])) {
		status_msg = "Be right back";
		new_status = msn_status_brb;
	} else if (!strcmp("AWY", tokens[1])) {
		status_msg = "Away";
		new_status = msn_status_away;
	} else if (!strcmp("PHN", tokens[1])) {
		status_msg = "On the phone";
		new_status = msn_status_phone;
	} else if (!strcmp("LUN", tokens[1])) {
		status_msg = "Out for lunch";
		new_status = msn_status_lunch;
	} else if (!strcmp("HDN", tokens[1])) {
		status_msg = "Hidden";
		new_status = msn_status_hidden;
	} else {
		status_msg = "Unknown";
	}

	if (buddy->status != new_status) {

		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.buff = status_msg;
		evt.from = buddy;
		evt.type = msn_evt_status_change;
		
		target_msn_session_event(cp, &evt);

		buddy->status = new_status;
	}

	pom_log(POM_LOG_TSHOOT "User \"%s\" (%s) is now %s", buddy->nick, buddy->account, status_msg);


	return POM_OK;
}

// Initial presence
int target_msn_handler_iln(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : ILN TrID status account type friendly_name capabilities

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 5) {
		pom_log(POM_LOG_DEBUG "ILN command incomplete");
		return POM_OK;
	}
	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	struct target_buddy_msn *buddy = NULL;
	char *at = strchr(tokens[3], '@'); // Basic verification
	if (at) {
		// MSNP 18->above add 1: in front of the account name
		char *account = strchr(tokens[3], ':');
		if (account)
			account++;
		else
			account = tokens[3];

		buddy = target_msn_session_found_buddy(cp, account, tokens[3], NULL);
	} else {
		pom_log(POM_LOG_DEBUG "Warning, invalid ILN message : %s", tokens[3]);
		return POM_OK;
	}

	int new_status = msn_status_unknown;
	char *status_msg = NULL;
	if (!strcmp("NLN", tokens[2])) {
		status_msg = "Available";
		new_status = msn_status_available;
	} else if (!strcmp("BSY", tokens[2])) {
		status_msg = "Busy";
		new_status = msn_status_busy;
	} else if (!strcmp("IDL", tokens[2])) {
		status_msg = "Idle";
		new_status = msn_status_idle;
	} else if (!strcmp("BRB", tokens[2])) {
		status_msg = "Be right back";
		new_status = msn_status_brb;
	} else if (!strcmp("AWY", tokens[2])) {
		status_msg = "Away";
		new_status = msn_status_away;
	} else if (!strcmp("PHN", tokens[2])) {
		status_msg = "On the phone";
		new_status = msn_status_phone;
	} else if (!strcmp("LUN", tokens[2])) {
		status_msg = "Out for lunch";
		new_status = msn_status_lunch;
	} else if (!strcmp("HDN", tokens[2])) {
		status_msg = "Hidden";
		new_status = msn_status_hidden;
	} else {
		status_msg = "Unknown";
	}

	if (buddy->status != new_status) {

		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.buff = status_msg;
		evt.from = buddy;
		evt.type = msn_evt_status_change;
		
		target_msn_session_event(cp, &evt);

		buddy->status = new_status;
	}

	pom_log(POM_LOG_TSHOOT "User \"%s\" (%s) is now %s", tokens[5], tokens[3], tokens[2]);

	return POM_OK;
}

// Someone signed off
int target_msn_handler_fln(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {
	
	// server : FLN account capabilities(optional)

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 2) {
		pom_log(POM_LOG_DEBUG "FLN command incomplete");
		return POM_OK;
	}
	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	char *at = strchr(tokens[1], '@'); // Basic verification
	char *account = NULL;
	if (at) {
		// MSNP 18->above add 1: in front of the account name
		account = strchr(tokens[1], ':');
		if (account)
			account++;
		else
			account = tokens[1];

	} else {
		pom_log(POM_LOG_DEBUG "Warning, invalid FLN message : %s", tokens[1]);
		return POM_OK;
	}

	struct target_buddy_msn *buddy = target_msn_session_found_buddy(cp, account, NULL, NULL);

	if (buddy == &cp->session->user) // Sometimes we receive FLN for ourself probably for caps
		return POM_OK;

	if (buddy->status != msn_status_offline) {

		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.buff = "Offline";
		evt.from = buddy;
		evt.type = msn_evt_status_change;
		
		target_msn_session_event(cp, &evt);

		buddy->status = msn_status_offline;
	}

	pom_log(POM_LOG_TSHOOT "User \"%s\" signed out", account);
	return POM_OK;
}

// File transfer (sharing invite)
int target_msn_handler_uun(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : UUN TrID account type length
	// server : UUN TrID OK
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 2) {
		pom_log(POM_LOG_DEBUG "UUN command incomplete");
		return POM_OK;
	}

	if (!strcmp(tokens[2], "OK")) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		return POM_OK;
	}

	char *at = strchr(tokens[2], '@');
	if (!at) {
		pom_log(POM_LOG_DEBUG "Unknown UUN message");
		return POM_OK;
	}

	unsigned int length = 0;
	if (sscanf(tokens[4], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid length received : %s", tokens[4]);
		return POM_OK;
	}

	if (length > 0)
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);

	target_msn_session_found_buddy(cp, tokens[2], NULL, NULL);
	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);


	return POM_OK;
}

// User status messsage
int target_msn_handler_uux(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : UUX TrID length
	// server : UUX TrID 0
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	unsigned int length = 0;
	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "UUX command incomplete");
		return POM_OK;
	}

	if (sscanf(tokens[2], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid length received : %s", tokens[2]);
		return POM_OK;
	}

	if (length > 0) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_status_msg);
		cp->msg[cp->curdir]->from = &cp->session->user;
	}

	return POM_OK;
}

// List of file names not to accept ... ho wait, what if I rename the file name ...
int target_msn_handler_gcf(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// MSNP 11
	// client : GCG Trid file
	// server : GCF TrID file length
	
	// MSNP 13 -> above
	// server : GCF Trid length
	

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "GCF command incomplete");
		return POM_OK;
	}

	unsigned int length = 0;

	if (sscanf(tokens[2], "%u", &length) != 1) {
		if (tok_num > 3) {
			if (sscanf(tokens[3], "%u", &length) != 1) {
				pom_log(POM_LOG_DEBUG "GCF command unhandled : %s", tokens[3]);
				return POM_OK;
			}
			target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		} else {
			target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		}
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	if (length > 0)
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);


	return POM_OK;
}

// Retrive your contacts via SOAP, then tell the servers what are your contact
int target_msn_handler_adl(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : ADL TrID length
	// server : ADL TrID OK
	// server : ADL 0 length

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "ADL command incomplete");
		return POM_OK;
	}

	unsigned int length = 0;
	if (!strcmp(tokens[2], "OK")) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	} else if (sscanf(tokens[2], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "ADL Invalid size received : %s", tokens[2]);
		return POM_OK;
	} else {
		unsigned int trid = 0;
		if (sscanf(tokens[1], "%u", &trid) != 1) {
			pom_log(POM_LOG_DEBUG "ADL invalid TrID : %s", tokens[1]);
			return POM_OK;
		}
		if (trid > 0)
			target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		else // server uses 0 as a TrID
			target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

		if (length > 0)
			cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);
	}
	return POM_OK;
}

// Remove ppl from my list
int target_msn_handler_rml(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : RML TrID length
	// server : RML TrID OK

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "RML command incomplete");
		return POM_OK;
	}

	unsigned int length = 0;
	if (!strcmp(tokens[2], "OK")) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	} else if (sscanf(tokens[2], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "RML Invalid size received : %s", tokens[2]);
		return POM_OK;
	} else {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		if (length > 0)
			cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);
	}

	return POM_OK;
}

// Server may not be sure if user is online ... So this command is there to ask user if he is online
int target_msn_handler_fqy(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {


	// client/server : FQY TrID length

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "FQY command incomplete");
		return POM_OK;
	}

	unsigned int length = 0;
	if (sscanf(tokens[2], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "RML Invalid size received : %s", tokens[2]);
		return POM_OK;
	} else {
		if (length > 0)
			cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);
	}

	return POM_OK;
}

// Client send a message
int target_msn_handler_uum(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : UUM TrID account networkid type length

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 6) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse UUM command");
		return POM_OK;
	}

	unsigned int length = 0;
	if (sscanf(tokens[5], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid size provided : %s", tokens[5]);
		return POM_OK;
	}

	struct target_connection_party_msn *to = NULL;

	if (strchr(tokens[2], '@') != NULL) { // We found an account 
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		to = target_msn_session_found_party(cp, tokens[2], NULL);
		if (length > 0)
			cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_msg);

	}

	if (length > 0) {
		if (to) {
			struct target_msg_msn *msg =  cp->msg[cp->curdir];
			msg->to = to->buddy;
		}
	}

	return POM_OK;
}

// Client received a message
int target_msn_handler_ubm(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : UBM account networkid type length

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 5) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse UBM command");
		return POM_OK;
	}

	unsigned int length = 0;
	if (sscanf(tokens[4], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid size provided : %s", tokens[4]);
		return POM_OK;
	}

	struct target_connection_party_msn *from = NULL;

	if (strchr(tokens[1], '@') != NULL) { // We found an account 
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		from = target_msn_session_found_party(cp, tokens[1], NULL);
		if (length > 0)
			cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_msg);
	}

	if (length > 0) {
		if (from) {
			struct target_msg_msn *msg =  cp->msg[cp->curdir];
			msg->from = from->buddy;
		}
	}

	return POM_OK;
}

// Sending email invite
int target_msn_handler_sdc(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : SDC TrID account locale_id? MSMSGS client_type X X friendly_name length
	// server : SDC TrID OK

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse SDC command");
		return POM_OK;
	}

	if (!strcmp(tokens[2], "OK")) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	} else {

		if (tok_num < 10) {
			pom_log(POM_LOG_DEBUG "Not enough tokens to parse SDC command");
			return POM_OK;
		}

		unsigned int length = 0;
		if (sscanf(tokens[9], "%u", &length) != 1) {
			pom_log(POM_LOG_DEBUG "Invalid size provided : %s", tokens[4]);
			return POM_OK;
		}

		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);

		if (length > 0) {
			cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_mail_invite);

			//target_msn_session_found_friendly_name(cp, tokens[8]);
			
			cp->msg[cp->curdir]->to = target_msn_session_found_buddy(cp, tokens[2], NULL, NULL);

		}

		pom_log(POM_LOG_TSHOOT "SDC : \"%s\" invites %s", tokens[8], tokens[2]);
	}
	
	
	return POM_OK;
}

// Sending email invite
int target_msn_handler_snd(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : SND TrID account locale_id? MSMSGS msmsgs
	// server : SND TrID OK

	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse SND command");
		return POM_OK;
	}

	if (!strcmp(tokens[2], "OK")) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	} else {

		if (tok_num < 6) {
			pom_log(POM_LOG_DEBUG "Not enough tokens to parse SND command");
			return POM_OK;
		}

		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);

		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.to = target_msn_session_found_buddy(cp, tokens[2], NULL, NULL);
		evt.type = msn_evt_mail_invite;

		target_msn_session_event(cp, &evt);

		pom_log(POM_LOG_TSHOOT "SND : invites %s", tokens[2]);
	}
	
	
	return POM_OK;
}

int target_msn_handler_qry(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : QRY TrID client_id length
	// server : QRY TrID
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 2) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse QRY command");
		return POM_OK;
	}

	if (tok_num > 3) {
		unsigned int length = 0;
		if (sscanf(tokens[3], "%u", &length) != 1) {
			pom_log(POM_LOG_DEBUG "Invalid QRY message : %s", tokens[3]);
			return POM_OK;
		}
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		if (length > 0)
			cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);

	} else {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
	}

	return POM_OK;
}

// Update our or remove friendly_name
int target_msn_handler_rea(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : REA TrID account friendly_name
	// server : REA TrID version account friendly_name
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 4) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse REA command");
		return POM_OK;
	}

	char *account = NULL, *friendly_name = NULL;

	if (tok_num > 4) {
		unsigned int length = 0;
		if (sscanf(tokens[2], "%u", &length) != 1) {
			pom_log(POM_LOG_DEBUG "Invalid REA message : %s", tokens[2]);
			return POM_OK;

		}
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		account = tokens[3];
		friendly_name = tokens[4];

	} else {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		account = tokens[2];
		friendly_name = tokens[3];
	}

	struct target_session_priv_msn *sess = cp->session;

	if (sess->user.account) {
		if (!strcmp(sess->user.account, account)) { // We're updating our own nick
			pom_log(POM_LOG_TSHOOT "User changed his nick to \"%s\"", friendly_name);
			target_msn_session_found_friendly_name(cp, friendly_name, &f->tv);
		} else { // Updating someone's nick
			target_msn_session_found_buddy(cp, account, friendly_name, NULL);
			pom_log(POM_LOG_TSHOOT "Buddy %s is now known as \"%s\"", account, friendly_name);
		}
	}

	return POM_OK;
}

// Not sure what this one does
int target_msn_handler_nfy(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : NFY PUT length
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse NFY command");
		return POM_OK;
	}

	unsigned int length = 0;
	if (sscanf(tokens[2], "%u", &length) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid NFY message : %s", tokens[2]);
		return POM_OK;
	}

	if (strcmp(tokens[1], "PUT")) {
		pom_log(POM_LOG_DEBUG "Unknown NFY command : %s", tokens[1]);
		// no return since we parsed the length
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	if (length > 0)
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);


	return POM_OK;
}

// Neither this one
int target_msn_handler_put(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// client : PUT TrID length
	// server : PUT TrID OK length
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 3) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse PUT command");
		return POM_OK;
	}

	char *length = NULL;

	if (tok_num > 3) {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);
		length = tokens[3];
	} else {
		target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_CLIENT);
		length = tokens[2];
	}

	unsigned int len = 0;
	if (sscanf(length, "%u", &len) != 1) {
		pom_log(POM_LOG_DEBUG "Invalid PUT message : %s", length);
		return POM_OK;

	}

	if (len > 0)
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(len, msn_payload_type_ignore);


	return POM_OK;
}

// Error handling
int target_msn_handler_error(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// server : XXX TrID length(optional)
	
	char *tokens[MSN_CMD_MAX_TOKEN];
	unsigned int tok_num = msn_cmd_tokenize(cp->buffer[cp->curdir], tokens);

	if (tok_num < 2) {
		pom_log(POM_LOG_DEBUG "Not enough tokens to parse the error");
		return POM_OK;
	}

	unsigned int length = 0;
	if (tok_num > 2) {
		if (sscanf(tokens[2], "%u", &length) != 1) {
			pom_log(POM_LOG_DEBUG "Invalid error message : %s", tokens[2]);
			return POM_OK;
		}
	}

	target_msn_chk_conn_dir(cp, f->ce->direction, MSN_DIR_FROM_SERVER);

	if (length > 0)
		cp->msg[cp->curdir] = msn_cmd_alloc_msg(length, msn_payload_type_ignore);


	return POM_OK;
}

// missing commands : ADC CVQ REM RMG
