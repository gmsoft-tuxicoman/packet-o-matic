/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2008 Guy Martin <gmsoft@tuxicoman.be>
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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "target_msn.h"
#include "target_msn_msgs.h"
#include "target_msn_session.h"

#include "ptype_bool.h"
#include "ptype_string.h"
#include "ptype_ipv4.h"
#include "ptype_uint16.h"


struct msn_cmd_handler msn_cmds[] = {

	{ "VER", target_msn_handler_ver },
	{ "CVR", target_msn_handler_cvr },
	{ "USR", target_msn_handler_usr },
	{ "XFR", target_msn_handler_xfr },
	{ "MSG", target_msn_handler_msg },
	{ "PRP", target_msn_handler_prp },
	{ "LSG", target_msn_handler_lsg },
	{ "LST", target_msn_handler_lst },
	{ "CHG", target_msn_handler_chg },
	{ "PNG", target_msn_handler_png },
	{ "QNG", target_msn_handler_qng },
	{ "UBX", target_msn_handler_ubx },
	{ "UBN", target_msn_handler_ubx }, // same as UBX
	{ "CAL", target_msn_handler_cal },
	{ "JOI", target_msn_handler_joi },
	{ "ANS", target_msn_handler_ans },
	{ "IRO", target_msn_handler_iro },
	{ "ACK", target_msn_handler_ack },
	{ "NAK", target_msn_handler_nak },
	{ "BYE", target_msn_handler_bye },
	{ "NOT", target_msn_handler_not },
	{ "RNG", target_msn_handler_rng },
	{ "OUT", target_msn_handler_out },
	{ "NLN", target_msn_handler_nln },
	{ "ILN", target_msn_handler_iln },
	{ "FLN", target_msn_handler_fln },
	{ "UUN", target_msn_handler_uun },
	{ "UUX", target_msn_handler_uux },
	{ "GCF", target_msn_handler_gcf },
	{ "ADL", target_msn_handler_adl },
	{ "RML", target_msn_handler_rml },
	{ "FQY", target_msn_handler_fqy },
	{ "241", target_msn_handler_fqy }, // same as FQY
	{ "SBS", target_msn_handler_ignore },
	{ "SBP", target_msn_handler_ignore },
	{ "BLP", target_msn_handler_ignore },
	{ "CHL", target_msn_handler_ignore },
	{ "QRY", target_msn_handler_ignore },
	{ "SYN", target_msn_handler_ignore },
	{ "GTC", target_msn_handler_ignore },
	{ "BPR", target_msn_handler_ignore },
	{ "URL", target_msn_handler_ignore },

	{ NULL, NULL}, // Terminating entry
};

static unsigned int match_undefined_id;
static struct target_mode *mode_default;

int target_register_msn(struct target_reg *r) {

	r->init = target_init_msn;
	r->process = target_process_msn;
	r->close = target_close_msn;
	r->cleanup = target_cleanup_msn;

	match_undefined_id = match_register("undefined");

	mode_default = target_register_mode(r->type, "dump", "Dump msn conversation and files");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "path", "/tmp", "Path were to dump files");

	return POM_OK;

}

int target_init_msn(struct target *t) {

	struct target_priv_msn *priv = malloc(sizeof(struct target_priv_msn));
	memset(priv, 0, sizeof(struct target_priv_msn));

	t->target_priv = priv;

	priv->path = ptype_alloc("string", NULL);

	if (!priv->path) {
		target_cleanup_msn(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "path", priv->path);

	return POM_OK;
}

int target_close_msn(struct target *t) {

	struct target_priv_msn *priv = t->target_priv;

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_msn(t, priv->ct_privs->ce, priv->ct_privs);
	}

	return POM_OK;
}

int target_cleanup_msn(struct target *t) {

	struct target_priv_msn *priv = t->target_priv;

	if (priv) {
			
		ptype_cleanup(priv->path);
		free(priv);

	}

	return POM_OK;
}

int target_process_msn(struct target *t, struct frame *f) {

	struct target_priv_msn *priv = t->target_priv;

	struct layer *lastl = f->l;
	while (lastl->next && lastl->next->type != match_undefined_id)
		lastl = lastl->next;

	if (lastl->payload_size == 0)
		return POM_OK;

	if (!f->ce)
		if (conntrack_create_entry(f) == POM_ERR)
			return POM_OK;


	struct target_conntrack_priv_msn *cp;

	cp = conntrack_get_target_priv(t, f->ce);

	if (!cp) {


		// New connection
		char tmp[NAME_MAX + 1];
		memset(tmp, 0, sizeof(tmp));
		if (layer_field_parse(f->l, PTYPE_STRING_GETVAL(priv->path), tmp, NAME_MAX) == POM_ERR) {
			pom_log(POM_LOG_WARN "Error while parsing the path");
			return POM_ERR;
		}

		cp = malloc(sizeof(struct target_conntrack_priv_msn));
		memset(cp, 0, sizeof(struct target_conntrack_priv_msn));

		cp->parsed_path = malloc(strlen(tmp) + 3);
		strcpy(cp->parsed_path, tmp);
		if (*(cp->parsed_path + strlen(cp->parsed_path) - 1) != '/')
			strcat(cp->parsed_path, "/");

		cp->server_dir = CE_DIR_UNK;
		conntrack_add_target_priv(cp, t, f->ce, target_close_connection_msn);


		struct target_session_priv_msn *sess;
		sess = malloc(sizeof(struct target_session_priv_msn));
		memset(sess, 0, sizeof(struct target_session_priv_msn));

		sess->refcount++;
		cp->session = sess;

		cp->fd = -1;

		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;

		// Probably a good time to load old info if we have some
		target_msn_session_load(t, cp);

	}

	if (!cp->ce)
		cp->ce = f->ce;

	// Split in lines
	char *payload = f->buff + lastl->payload_start;
	unsigned int plen = lastl->payload_size;

	while (plen > 0) {

		if (plen > f->bufflen) {
			pom_log(POM_LOG_ERR "Internal error, payload length greater than buffer length");
			return POM_ERR;
		}

		int dir = 0;
		if (f->ce->direction == CE_DIR_FWD) {
			dir = 0;
		} else {
			dir = 1;
		}
		cp->curdir = dir;
		
		struct target_msg_msn *msg = cp->msg[dir];

		if (msg) { // It's a message, get the full payload in the buffer
			if (cp->buffer_len[dir] < msg->tot_len + 1) {
				cp->buffer[dir] = realloc(cp->buffer[dir], msg->tot_len + 1);
				cp->buffer_len[dir] = msg->tot_len + 1;
			}
			int remaining = msg->tot_len - msg->cur_len;
			if (remaining > plen)
				remaining = plen;
			memcpy(cp->buffer[dir] + msg->cur_len, payload, remaining);
			*(cp->buffer[dir] + msg->cur_len + remaining) = 0; // Terminate payload by NULL
			plen -= remaining;
			payload += remaining;
			msg->cur_len += remaining;

			if (msg->cur_len < msg->tot_len)
				return POM_OK; // Next packet will have the rest of the buffer

		} else { // Get only current msg in the buffer
			// First see if we already have something in the buffer
			char *end = NULL;
			if (cp->buffer[dir] && *cp->buffer[dir])
				end = strstr(cp->buffer[dir], "\r\n");

			if (!end) { // Nothing was found let's look into our payload
				end = memchr(payload, '\r', plen); // We enforce /r/n
				if (end) {
					if (end + 1 < payload + plen) {
						if (*(end + 1) == '\n')
							*end = 0;
						else
							end = NULL;
					} else
						end = NULL;
				}
				if (!end) {
					if (cp->buffer_len[dir] < plen + 1) {
						cp->buffer[dir] = realloc(cp->buffer[dir], plen + 1);
						cp->buffer_len[dir]  = plen + 1;
					}
					// Save current packet and go to next one
					memcpy(cp->buffer[dir], payload, plen);
					cp->buffer[dir][plen] = 0; // Terminate string
					return POM_OK; // Wait for EOL on next message
				} else {
					int len = end - payload + 2;
					int bufflen = len + 1;
					if (cp->buffer[dir])
						bufflen += strlen(cp->buffer[dir]);
					if (cp->buffer_len[dir] < bufflen + 1) {
						cp->buffer[dir] = realloc(cp->buffer[dir], bufflen + 1);
						cp->buffer[dir][0] = 0;
						cp->buffer_len[dir] = bufflen + 1;
					}

					strcat(cp->buffer[dir], payload);
					plen -= len;
					payload += len;
				}
			} else {
				*end = 0;
			}
		}

		int res = POM_OK;
		if (!msg) {
			pom_log(POM_LOG_TSHOOT "Command : %s", cp->buffer[dir]);
			res = target_process_line_msn(t, cp, f);
		} else {
			switch (msg->payload_type) {
				case msn_payload_type_msg:
					res = target_process_msg_msn(t, cp, f);
					break;
				case msn_payload_type_ignore:
					res = target_process_payload_ignore_msn(t, cp, f);
					break;
				default:
					pom_log(POM_LOG_ERR "Invalid state");
					return POM_ERR;
			}
		}

		if (res == POM_ERR)
			return POM_ERR;

		*cp->buffer[dir] = 0;


	}
	

	return POM_OK;
}

int target_process_line_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {


	int (*handler) (struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
	handler = NULL;

	int i;
	for (i = 0; msn_cmds[i].cmd; i++) {
		if (!memcmp(msn_cmds[i].cmd, cp->buffer[cp->curdir], 3)) {
			handler = msn_cmds[i].handler;
			break;
		}
	}

	if (!strlen(cp->buffer[cp->curdir]))
		return POM_OK;


	if (!handler) {
		int error = 0;
		if (sscanf(cp->buffer[cp->curdir], "%u", &error)) {
			pom_log(POM_LOG_TSHOOT "Received error %u : %s", error, cp->buffer[cp->curdir]);
			return POM_OK;
		}
		pom_log(POM_LOG_DEBUG "Unhandled command %3s", cp->buffer[cp->curdir]);
		return POM_OK;
	}

	return (*handler) (t, cp, f);


}


int target_process_payload_ignore_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	struct target_msg_msn *m =  cp->msg[cp->curdir];
	int len = m->tot_len - m->cur_pos;
	pom_log(POM_LOG_TSHOOT "Happily ignored %u of payload", len);

	target_free_msg_msn(cp, cp->curdir);

	return POM_OK;
}

int target_msn_handler_ignore(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {
	
	char *ign = cp->buffer[cp->curdir];
	pom_log(POM_LOG_TSHOOT "Ignoring command : %s", ign);
	return POM_OK;
}

// Protocol version negociation
int target_msn_handler_ver(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *ver = cp->buffer[cp->curdir] + 4;

	char *version = NULL;
	int token_id = 0;

	char *str, *token, *saveptr = NULL;
	for (str = ver; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				//pom_log(POM_LOG_TSHOOT "TrID is %s", token);
				break;
			case 1:
				version = token;
				break;
			case 2: // Multiple version found, this is not a server reply
				target_msn_set_connection_direction(cp, f->ce->direction, 0);
				version = NULL;
				break;
			default:
				break;
		}
		token_id++;

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

	char *cvr = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	char *str, *token, *saveptr = NULL;
	for (str = cvr; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				//pom_log(POM_LOG_TSHOOT "TrID is %s", token);
				break;
			case 1:
				if (cp->server_dir == CE_DIR_UNK) {
					if (!memcmp(token, "0x", 2)) { // It's client direction
						target_msn_set_connection_direction(cp, f->ce->direction, 0);
					} else { // It's server direction
						target_msn_set_connection_direction(cp, f->ce->direction, 1);
					}
				}
				break;
			case 8:
				if (cp->server_dir != f->ce->direction) { // We can catch client's login here
					target_msn_session_found_account(cp, token);
				}
			default:
				break;
		}
		token_id++;

	}


	return POM_OK;
}

// Authentication
int target_msn_handler_usr(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *usr = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	enum usr_types {
		usr_undef,
		usr_twn,
		usr_twn_i, // Set after we see a TWN I msg
		usr_sso,
		usr_ok,
	};

	int usr_type = usr_undef;

	char *str, *token, *saveptr = NULL;
	for (str = usr; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0: 
				//pom_log(POM_LOG_TSHOOT "TrID is %s", token);
				break;
			case 1: {
				
				char *at = strchr(token, '@');
				if (at) {
					target_msn_set_connection_direction(cp, f->ce->direction, 0);
					target_msn_session_found_account(cp, token);
					return POM_OK; // We don't care about the rest
				} else if (!memcmp(token, "OK", 2)) {
					usr_type = usr_ok;
					// Only server can say OK
					target_msn_set_connection_direction(cp, f->ce->direction, 1);
				} else if (!memcmp(token, "TWN", 3)) {
					usr_type = usr_twn;
				} else if (!memcmp(token, "SSO", 3)) {
					usr_type = usr_sso;
				} else {
					pom_log(POM_LOG_DEBUG "Unhandled USR message with %s parameter", token);
					return POM_OK;
				}
				break;
			}
			case 2:
				if (usr_type == usr_ok) {
					// Account name is supposed to be here
					target_msn_session_found_account(cp, token);
					break;
				} else if (usr_type == usr_twn) {
					if (*token == 'I') {
						usr_type = usr_twn_i;
						target_msn_set_connection_direction(cp, f->ce->direction, 0);
						break;
					}

				}
				break;
			case 3:
				if (usr_type == usr_twn_i) {
					target_msn_session_found_account(cp, token);
					break;
				}
				break;
			default:
				break;
		}
		token_id++;

	}


	return POM_OK;
}

// Transfer to another server
int target_msn_handler_xfr(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *xfr = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	char *address = NULL;

	char *str, *token, *saveptr = NULL;
	for (str = xfr; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				//pom_log(POM_LOG_TSHOOT "TrID is %s", token);
				break;
			case 1:
				if (!memcmp("NS", token, 2) && !memcmp("SB", token, 2)) {
					pom_log(POM_LOG_DEBUG "Invalid XFR message : %s", token);
					return POM_OK;
				}
				break;
			case 2:
				// This must be the address
				address = token;
				break;
			default:
				break;
		}
		token_id++;

	}

	if (address) {

		target_msn_set_connection_direction(cp, f->ce->direction, 1);
		struct target_conntrack_priv_msn *new_cp = target_msn_conntrack_priv_fork(t, cp, f);
		target_msn_add_expectation(t, new_cp, f, address);

	}


	return POM_OK;
}

// Message
int target_msn_handler_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *msg = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	char *account = NULL, *nick = NULL;

	char *str, *token, *saveptr = NULL;
	for (str = msg; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				if (cp->server_dir == CE_DIR_UNK) { // Direction unknown, let's deduce it
					int trid = 0;
					if (strchr(token, '@') != NULL) { // We found an account name -> connection from SB
						target_msn_set_connection_direction(cp, f->ce->direction, 1);
						account = token;
					} else if (sscanf(token, "%u", &trid) == 1) { // We found a TrID -> connection to NS or SB
						target_msn_set_connection_direction(cp, f->ce->direction, 0);
					} else { // Can only be connection from NS
						target_msn_set_connection_direction(cp, f->ce->direction, 1);
						account = token;
					}
				} else {
					if (cp->server_dir == f->ce->direction) {
						// Must be account name
						account = token;
					} else {
						int trid = 0;
						if (sscanf(token, "%u", &trid) != 1) {
							pom_log(POM_LOG_DEBUG "MSG did not contain a valid TrID");
							return POM_OK;
						}
					}
				}

				break;
			case 1:
				if (cp->server_dir == f->ce->direction) {
					nick = token;
				} else {
					// We don't care about the Ack type
				}
				break;
			case 2: {
				unsigned int size = 0;
				if (sscanf(token, "%u", &size) != 1) {
					pom_log(POM_LOG_DEBUG "Invalid size provided : %s", token);
					return POM_OK;
				}
				struct target_msg_msn *my_msg = NULL;
				if (size > 0) {
					my_msg = malloc(sizeof(struct target_msg_msn));
					memset(my_msg, 0, sizeof(struct target_msg_msn));
					my_msg->tot_len = size;
					my_msg->cur_len = 0;
					my_msg->payload_type = msn_payload_type_msg;
					cp->msg[cp->curdir] = my_msg;
				} else {
					break;
				}
				if (cp->server_dir == f->ce->direction) {
					if (!account || !nick) {
						pom_log(POM_LOG_DEBUG "Warning, account or nick is null.");
						return POM_OK;
					}

					my_msg->from = malloc(strlen(account) + 1);
					strcpy(my_msg->from, account);

				}
				break;
			}
			default:
				break;
		}
		token_id++;

	}

	return POM_OK;
}

// Getting/setting personal details
int target_msn_handler_prp(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *prp = cp->buffer[cp->curdir] + 4;

	enum msn_prp_types {
		msn_prp_type_unk = 0, // dummy type
		msn_prp_type_phh, // home phone number
		msn_prp_type_phw, // work phone number
		msn_prp_type_phm, // mobile phone number
		msn_prp_type_mob, // can ppl call mobile device ?
		msn_prp_type_mbe, // mobile device enabled ?
		msn_prp_type_wwe, // direct paging = 2, else 0
		msn_prp_type_mfn, // my friendly name
		msn_prp_type_set_mfn, // set my friendly name

	};

	int prp_type = msn_prp_type_unk;
	int trid = 0;

	int token_id = 0;

	char *str, *token, *saveptr = NULL;
	for (str = prp; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0: {
				if (!memcmp(token, "PHH", 3)) {
					prp_type = msn_prp_type_phh;	
				} else if (!memcmp(token, "PHW", 3)) {
					prp_type = msn_prp_type_phw;
				} else if (!memcmp(token, "PHM", 3)) {
					prp_type = msn_prp_type_phm;
				} else if (!memcmp(token, "MOB", 3)) {
					prp_type = msn_prp_type_mob;
				} else if (!memcmp(token, "MBE", 3)) {
					prp_type = msn_prp_type_mbe;
				} else if (!memcmp(token, "WWE", 3)) {
					prp_type = msn_prp_type_wwe;
				} else if (!memcmp(token, "MFN", 3)) {
					prp_type = msn_prp_type_mfn;
				} else if (sscanf(token, "%u", &trid) == 1) {
					prp_type = msn_prp_type_set_mfn;
				} else {
					prp_type = msn_prp_type_unk;
				}
				break;
			}
			case 1:
					switch (prp_type) {
						case msn_prp_type_phh:
							pom_log(POM_LOG_TSHOOT "Home phome number : %s", token);
							break;
						case msn_prp_type_phw:
							pom_log(POM_LOG_TSHOOT "Work phome number : %s", token);
							break;
						case msn_prp_type_phm:
							pom_log(POM_LOG_TSHOOT "Mobile phome number : %s", token);
							break;
						case msn_prp_type_mob:
							pom_log(POM_LOG_TSHOOT "Can pll call mobile device ? : %s", token);
							break;
						case msn_prp_type_mbe:
							pom_log(POM_LOG_TSHOOT "Mobile device enabled ? : %s", token);
							break;
						case msn_prp_type_wwe:
							pom_log(POM_LOG_TSHOOT "Direct paging ? : %s", token);
							break;
						case msn_prp_type_mfn:
							pom_log(POM_LOG_TSHOOT "My friendly name : \"%s\"", token);
							break;
						case msn_prp_type_set_mfn:
							break; // Nothing to do
						default:
							pom_log(POM_LOG_DEBUG "Unknown PRP type : %s", token);
							break;
					}
					break;
				case 2:
					if (prp_type == msn_prp_type_set_mfn) {
						pom_log(POM_LOG_TSHOOT "My friendly name set to \"%s\"", token);
					} else {
						pom_log(POM_LOG_DEBUG "Unknown extra parameter %s", token);
					}
					break;

			
			default:
				break;
		}
		token_id++;

	}

	return POM_OK;
}


// List of group
int target_msn_handler_lsg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *lsg = cp->buffer[cp->curdir] + 3;

	if (f->ce->direction != cp->server_dir) {
		pom_log(POM_LOG_TSHOOT "LSG not comming from server (or server dir unknown), ignoring.");
		return POM_OK;
	}

	int token_id = 0;

	// Allright, lets try to parse that one right as well
	// AFAICS, old syntax has 3 args while new has only 2
	
	char *tk1 = NULL, *tk2 = NULL;
	int old_syntax = 0;

	char *str, *token, *saveptr = NULL;
	for (str = lsg; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0: 
				tk1 = token;
				break;
			case 1:
				tk2 = token;
				break;
			case 2:
				old_syntax = 1;
				break;

			default:
				break;
		}
		token_id++;

	}

	if (old_syntax) {
		// Allright, make sure that that's it
		int id;
		if (sscanf(tk1, "%u", &id) != 1) {
			pom_log(POM_LOG_DEBUG "LSG: Invalid group ID received");
			return POM_OK;
		}
		return target_msn_session_found_group(cp, tk2, tk1);

	} else {
		// Could check the GUID but too lazy
		return target_msn_session_found_group(cp, tk1, tk2);
	}
	
	return POM_OK;
}


// List of contacts
int target_msn_handler_lst(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *lst = cp->buffer[cp->curdir] + 3;

	if (f->ce->direction != cp->server_dir) {
		pom_log(POM_LOG_DEBUG "LST not comming from server (or server dir unknown), ignoring.");
		return POM_OK;
	}


	int token_id = 0;

	char *account = NULL, *nick = NULL, *group = NULL;

	// Okay, so microsoft fscking SUX ! that's an assertion
	// Let's try to make sens of whatever the server will send
	// Stupid protocol has like 5 different syntax for the same command
	// Who the hell needs 15 different versions of a protocol ???
	// They are probably too st00pid to get it right

	while (*lst == ' ')
		lst++;

	int new_syntax = 0;
	if (!memcmp(lst, "N=", 2)) // New syntax alway give account prepended with N=
		new_syntax = 1;


	char *str, *token, *saveptr = NULL;
	for (str = lst; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0: {
				if (new_syntax)
					account = token + 2;
				else
					account = token;
					
				break;
			}
			case 1:
				if (new_syntax) {
					if (!memcmp(token, "F=", 2)) {
						nick = token + 2;
					}
					// else dunno what this is
				} else {
					nick = token;
				}
				break;
			case 3:
				if (!new_syntax)
					group = token;
				break;
			case 5:
				if (new_syntax)
					group = token;
				break;

			default:
				break;
		}
		token_id++;

	}
	
	if (nick && account) {
		pom_log(POM_LOG_TSHOOT "Account in the list : \"%s\" (%s)", nick, account);
		return target_msn_session_found_buddy(cp, account, nick, group);
	}

	return POM_OK;
}


// Change status
int target_msn_handler_chg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *chg = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	enum msn_chg_types {
		msn_chg_type_unk = 0, // dummy type
		msn_chg_type_nln, // available
		msn_chg_type_bsy, // busy
		msn_chg_type_idl, // idle
		msn_chg_type_brb, // be right back
		msn_chg_type_awy, // away
		msn_chg_type_phn, // on the phone
		msn_chg_type_lun, // out for lunch
	};

	unsigned int status = 0, cap = 0;
	char *descr = NULL;
	char *str, *token, *saveptr = NULL;
	for (str = chg; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				//pom_log(POM_LOG_TSHOOT "TrID is %s", token);
				break;
			case 1:
				if (!memcmp("NLN", token, 3)) {
					status = msn_chg_type_nln;
				} else if (!memcmp("BSY", token, 3)) {
					status = msn_chg_type_bsy;
				} else if (!memcmp("IDL", token, 3)) {
					status = msn_chg_type_idl;
				} else if (!memcmp("BRB", token, 3)) {
					status = msn_chg_type_brb;
				} else if (!memcmp("AWY", token, 3)) {
					status = msn_chg_type_awy;
				} else if (!memcmp("PHN", token, 3)) {
					status = msn_chg_type_phn;
				} else if (!memcmp("LUN", token, 3)) {
					status = msn_chg_type_lun;
				} else {
					status = msn_chg_type_unk;
				}
				break;
			case 2:
				if (sscanf(token, "%u", &cap) != 1) {
					pom_log(POM_LOG_DEBUG "Invalid capability received");
					return POM_OK;
				}
				break;
			case 3:
				descr = token;
				break;
			default:
				break;
		}
		token_id++;

	}

	if (status && cap && descr) {
		char *msg = NULL;
		switch (status) {
			case msn_chg_type_nln:
				msg = "Available";
				break;
			case msn_chg_type_bsy:
				msg = "Busy";
				break;
			case msn_chg_type_idl:
				msg = "Idle";
				break;
			case msn_chg_type_brb:
				msg = "Be right back";
				break;
			case msn_chg_type_awy:
				msg = "Away";
				break;
			case msn_chg_type_phn:
				msg = "On the phone";
				break;
			case msn_chg_type_lun:
				msg = "Out for lunch";
				break;
			default:
				break;

		}
		pom_log(POM_LOG_TSHOOT "Status changed : %s", msg);
	}


	return POM_OK;
}

// PING
int target_msn_handler_png(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	pom_log(POM_LOG_TSHOOT "PING from client");
	target_msn_set_connection_direction(cp, f->ce->direction, 0);
	return POM_OK;
}

// PONG
int target_msn_handler_qng(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	pom_log(POM_LOG_TSHOOT "PONG from server");
	target_msn_set_connection_direction(cp, f->ce->direction, 1);
	return POM_OK;
}

// Set your personal message
int target_msn_handler_ubx(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *ubx = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	int size = 0;

	char *str, *token, *saveptr = NULL;
	for (str = ubx; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				break;
			case 1:
				// Either networkid or size. If netid, it will be overwritten by next arg
				if (sscanf(token, "%u", &size) != 1) {
					pom_log(POM_LOG_DEBUG "UBX Invalid size received or network ID : %s", token);
					return POM_OK;
				}
				break;
			case 2:
				// Previous field must have been network id
				if (sscanf(token, "%u", &size) != 1) {
					pom_log(POM_LOG_DEBUG "UBX Invalid size received", token);
					return POM_OK;
				} 
			default:
				break;
		}
		token_id++;

	}

	if (size > 0) {
		struct target_msg_msn *msg = malloc(sizeof(struct target_msg_msn));
		memset(msg, 0, sizeof(struct target_msg_msn));
		msg->tot_len = size;
		msg->cur_len = 0;
		msg->payload_type = msn_payload_type_ignore;
		cp->msg[cp->curdir] = msg;
	}

	return POM_OK;
}


// Invite user to switchboard
int target_msn_handler_cal(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *cal = cp->buffer[cp->curdir] + 4;

	int token_id = 0;
	struct target_connection_party_msn *party = NULL;

	char *str, *token, *saveptr = NULL;
	for (str = cal; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				//pom_log(POM_LOG_TSHOOT "TrID is %s", token);
				break;
			case 1: {
				char *at = strchr(token, '@');
				if (at) {
					struct target_connection_party_msn *tmp = cp->parts;
					while (tmp) {
						if (!strcmp(tmp->account, token)) {
							party = tmp;
							break;
						}
						tmp = tmp->next;
					}

					if (!party) {

						pom_log(POM_LOG_TSHOOT "CAL: User %s was invited to the conversation", token);
						struct target_connection_party_msn *party;
						party = malloc(sizeof(struct target_connection_party_msn));
						memset(party, 0, sizeof(struct target_connection_party_msn));
						party->account = malloc(strlen(token) + 1);
						strcpy(party->account, token);

						party->next = cp->parts;
						cp->parts = party;
						target_msn_set_connection_direction(cp, f->ce->direction, 0);
					}
				} else if (!memcmp(token, "RINGING", strlen("RINGING"))) {
					target_msn_set_connection_direction(cp, f->ce->direction, 1);
				} else {
					pom_log(POM_LOG_DEBUG "Unhandled CAL message %s", token);
				}
				break;
			}
			default:
				break;
		}
		token_id++;

	}

	return POM_OK;
}

// User joined switchboard
int target_msn_handler_joi(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *joi = cp->buffer[cp->curdir] + 4;

	int token_id = 0;
	struct target_connection_party_msn *party = cp->parts;

	char *str, *token, *saveptr = NULL;
	for (str = joi; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		
		switch (token_id) {
			case 0: {
				struct target_connection_party_msn *tmp = cp->parts;
				while (tmp) {
					if (!strcmp(tmp->account, token)) {
						party = tmp;
						break;
					}
					tmp = tmp->next;
				}

				if (!party) {

					pom_log(POM_LOG_TSHOOT "JOI: Warning, user %s has join but wasn't invited", token);
					party = malloc(sizeof(struct target_connection_party_msn));
					memset(party, 0, sizeof(struct target_connection_party_msn));
					party->account = malloc(strlen(token) + 1);
					strcpy(party->account, token);

					if (cp->parts) {
						pom_log(POM_LOG_TSHOOT "More than one party joined !");
					}

					struct target_connection_party_msn *tmp = cp->parts;
					if (!tmp) {
						cp->parts = party;
					} else {
						while (tmp->next)
							tmp = tmp->next;
						tmp->next = party;
					}
				}
				break;
			}
			case 1:
				if (party->nick)
					free(party->nick);
				party->nick = malloc(strlen(token) + 1);
				strcpy(party->nick, token);
				pom_log(POM_LOG_TSHOOT "JOI: User \"%s\" (%s) has joined the conversation", party->nick, party->account);
				target_msn_set_connection_direction(cp, f->ce->direction, 1);
				party->joined = 1;
				break;

			default:
				break;
		}
		token_id++;

	}

	if (party) {
		struct target_conv_event_msn evt;
		memset(&evt, 0, sizeof(struct target_conv_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.from = party->account;
		evt.type = target_conv_event_type_user_join;

		target_msn_session_conv_event(cp, &evt);
	}	

	return POM_OK;
}

// List of parties in the conversation
int target_msn_handler_iro(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *iro = cp->buffer[cp->curdir] + 4;

	int token_id = 0;
	struct target_connection_party_msn *party = NULL;

	char *str, *token, *saveptr = NULL;
	for (str = iro; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				break;
			case 1:
				break;
			case 2:
				break;
			case 3: {
				struct target_connection_party_msn *tmp = cp->parts;
					
				while (tmp) {
					if (!strcmp(tmp->account, token)) {
						party = tmp;
						break;
					}
					tmp = tmp->next;
				}

				if (!party) {

					party = malloc(sizeof(struct target_connection_party_msn));
					memset(party, 0, sizeof(struct target_connection_party_msn));
					party->account = malloc(strlen(token) + 1);
					strcpy(party->account, token);

					if (cp->parts) {
						pom_log(POM_LOG_TSHOOT "More than one party joined !");
					}

					struct target_connection_party_msn *tmp = cp->parts;
					if (!tmp) {
						cp->parts = party;
					} else {
						while (tmp->next)
							tmp = tmp->next;
						tmp->next = party;
					}
				}
				break;
			}
			case 4:
				if (party->nick)
					free(party->nick);
				party->nick = malloc(strlen(token) + 1);
				strcpy(party->nick, token);
				pom_log(POM_LOG_TSHOOT "IRO: User \"%s\" (%s) has joined the conversation", party->nick, party->account);
				target_msn_set_connection_direction(cp, f->ce->direction, 1);
				party->joined = 1;
				break;

			default:
				break;
		}
		token_id++;

	}

	if (party) {
		struct target_conv_event_msn evt;
		memset(&evt, 0, sizeof(struct target_conv_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.from = party->account;
		evt.type = target_conv_event_type_user_join;

		target_msn_session_conv_event(cp, &evt);
	}

	return POM_OK;
}

// Verify identity to switchboard
int target_msn_handler_ans(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *ans = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	char *str, *token, *saveptr = NULL;
	for (str = ans; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				break;
			case 1: {
				char *at = strchr(token, '@'); // Basic verification
				if (at) {
					target_msn_session_found_account(cp, token);
					target_msn_set_connection_direction(cp, f->ce->direction, 0);
				} else if (!strcmp("OK", token)) {
					target_msn_set_connection_direction(cp, f->ce->direction, 1);
				} else {
					pom_log(POM_LOG_DEBUG "Unhandled ASN message : %s", token);
				}
				break;
			}
			default:
				break;
		}
		token_id++;

	}

	return POM_OK;
}

// Ack of MSG
int target_msn_handler_ack(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	target_msn_set_connection_direction(cp, f->ce->direction, 1);
	return POM_OK;
}

// MSG wasn't received
int target_msn_handler_nak(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	target_msn_set_connection_direction(cp, f->ce->direction, 1);
	return POM_OK;
}

// Contact leaves conversation
int target_msn_handler_bye(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *bye = cp->buffer[cp->curdir] + 4;
	while (*bye == ' ')
		bye++;
	char *at = strchr(bye, '@');
	if (at) {
		struct target_connection_party_msn *tmp = cp->parts;
		while (tmp) {
			if (!strcmp(tmp->account, bye)) {
				break;
			}
			tmp = tmp->next;
		}
		if (!tmp) {
			pom_log(POM_LOG_DEBUG "BYE: User %s not found in the list", bye);
		} else {
			pom_log(POM_LOG_TSHOOT "BYE: User %s left the conversation", bye);
			tmp->joined = 0;
		}

		struct target_conv_event_msn evt;
		memset(&evt, 0, sizeof(struct target_conv_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.from = bye;
		evt.type = target_conv_event_type_user_leave;

		target_msn_session_conv_event(cp, &evt);
	}


	return POM_OK;
}

// Notification
int target_msn_handler_not(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *not = cp->buffer[cp->curdir] + 4;
	while (*not == ' ')
		not++;
	unsigned int size = 0;
	if (sscanf(not, "%u", &size) == 1) {
		struct target_msg_msn *msg = malloc(sizeof(struct target_msg_msn));
		memset(msg, 0, sizeof(struct target_msg_msn));
		msg->tot_len = size;
		msg->cur_len = 0;
		msg->payload_type = msn_payload_type_ignore;
		cp->msg[cp->curdir] = msg;
	} else {
		pom_log(POM_LOG_DEBUG "NOT: Invalid size received : %s", not);
		return POM_OK;
	}
	return POM_OK;
}

// Someone wants to chat with you
int target_msn_handler_rng(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *rng = cp->buffer[cp->curdir] + 4;
	
	int token_id = 0;

	char *address = NULL;

	struct target_connection_party_msn *party = NULL;
	char *account = NULL;

	char *str, *token, *saveptr = NULL;
	for (str = rng; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				//pom_log(POM_LOG_TSHOOT "SessionID is %s", token);
				break;
			case 1:
				// This must be the address
				address = token;
				break;
			case 2:
				if (memcmp("CKI", token, 3)) {
					pom_log(POM_LOG_INFO "Invalid RNG message : %s", token);
					return POM_OK;
				}
				break;
			case 3:
				// auth string
				break;
			case 4: {
				account = token;
				char *at = strchr(token, '@');
				if (!at) {
					pom_log(POM_LOG_INFO "Invalid RNG message : %s", token);
					return POM_OK;
				}
				break;	
			}
			case 5:
				party = malloc(sizeof(struct target_connection_party_msn));
				memset(party, 0, sizeof(struct target_connection_party_msn));
				party->account = malloc(strlen(account) + 1);
				strcpy(party->account, account);
				party->nick = malloc(strlen(token) + 1);
				strcpy(party->nick, token);
				party->next = cp->parts;
				cp->parts = party;
				break;
			default:
				break;
		}
		token_id++;

	}

	if (address) {

		target_msn_set_connection_direction(cp, f->ce->direction, 1);
		struct target_conntrack_priv_msn *new_cp = target_msn_conntrack_priv_fork(t, cp, f);
		target_msn_add_expectation(t, new_cp, f, address);


	}


	return POM_OK;
}

// User is disconnecting
int target_msn_handler_out(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {
	
	char *account = "Unknown";
	if (cp->session->account)
		account = cp->session->account;

	pom_log(POM_LOG_DEBUG "OUT: User %s signed out", account);
	target_msn_set_connection_direction(cp, f->ce->direction, 0);
	return POM_OK;
}

// Change of presence
int target_msn_handler_nln(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *nln = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	int has_netid = 1;
	char *status_code = NULL, *account = NULL, *nick = NULL;

	char *str, *token, *saveptr = NULL;
	for (str = nln; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				status_code = token;
				break;
			case 1: {
				char *at = strchr(token, '@'); // Basic verification
				if (at) {
					account = token;
				} else {
					pom_log(POM_LOG_DEBUG "Warning, invalid NLN message : %s", token);
					return POM_OK;
				}
				break;
			}
			case 2: {
				char *tmp = token;
				while (*tmp) {
					if (*tmp < '0' || *tmp > '9') {
						has_netid = 0;
						break;
					}
					tmp++;
				}
				if (!has_netid) {
					nick = token;
				}
				break;
			}
			case 3:
				if (has_netid) 
					nick = token;
				pom_log(POM_LOG_TSHOOT "User \"%s\" (%s) is now %s", nick, account, status_code);
				break;
			default:
				break;
		}
		token_id++;

	}

	return POM_OK;
}

// Initial presence
int target_msn_handler_iln(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *iln = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	int has_netid = 1;
	char *status_code = NULL, *account = NULL, *nick = NULL;

	char *str, *token, *saveptr = NULL;
	for (str = iln; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0: {
				int trid = 0;
				if (sscanf(token, "%u", &trid) != 1) {
					pom_log(POM_LOG_DEBUG "Invalid TrID received in ILN message : %s", token);
					return POM_OK;
				}
				break;
			}
			case 1:
				status_code = token;
				break;
			case 2: {
				char *at = strchr(token, '@'); // Basic verification
				if (at) {
					account = token;
				} else {
					pom_log(POM_LOG_DEBUG "Warning, invalid NLN message : %s", token);
					return POM_OK;
				}
				break;
			}
			case 3: {
				char *tmp = token;
				while (*tmp) {
					if (*tmp < '0' || *tmp > '9') {
						has_netid = 0;
						break;
					}
					tmp++;
				}
				if (!has_netid) {
					nick = token;
				}
				break;
			}
			case 4:
				if (has_netid) 
					nick = token;
				pom_log(POM_LOG_TSHOOT "User \"%s\" (%s) is now %s", nick, account, status_code);
				break;
			default:
				break;
		}
		token_id++;

	}

	// Received from the server
	target_msn_set_connection_direction(cp, f->ce->direction, 1);

	return POM_OK;
}

// Someone signed off
int target_msn_handler_fln(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *fln = cp->buffer[cp->curdir] + 4;
	while (*fln == ' ')
		fln++;
	char *at = strchr(fln, '@');
	if (at) {
		char *end = strchr(at, ' ');
		if (end)
			*end = 0;
		pom_log(POM_LOG_TSHOOT "FLN: User %s signed out", fln);
	}
	return POM_OK;
}

// User status message
int target_msn_handler_uun(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	target_msn_set_connection_direction(cp, f->ce->direction, 1);
	return POM_OK;
}

// User status messsage
int target_msn_handler_uux(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *uux = cp->buffer[cp->curdir] + 4;

	
	int token_id = 0;

	int size = 0;

	char *str, *token, *saveptr = NULL;
	for (str = uux; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				break;
			case 1:
				if (sscanf(token, "%u", &size) != 1) {
					pom_log(POM_LOG_DEBUG "UUX Invalid size received or network ID : %s", token);
					return POM_OK;
				}
				break;
		}
		token_id++;

	}

	if (size > 0) {
		struct target_msg_msn *msg = malloc(sizeof(struct target_msg_msn));
		memset(msg, 0, sizeof(struct target_msg_msn));
		msg->tot_len = size;
		msg->cur_len = 0;
		msg->payload_type = msn_payload_type_ignore;
		cp->msg[cp->curdir] = msg;
	}

	return POM_OK;
}

// List of file names not to accept ... ho wait, what if I rename the file name ...
int target_msn_handler_gcf(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *gcf = cp->buffer[cp->curdir] + 4;

	int token_id = 0;
	int size = 0;

	char *str, *token, *saveptr = NULL;
	for (str = gcf; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				//pom_log(POM_LOG_TSHOOT "TrID is %s", token);
				break;
			case 1: 
				// Try to parse the size
				sscanf(token, "%u", &size);
				break;
			case 2: 
				// Or parse it now if any
				if (sscanf(token, "%u", &size) != 1) {
					pom_log(POM_LOG_DEBUG "GCF : Invalid size");
					return POM_OK;
				}
				break;
			default:
				break;
		}
		token_id++;

	}

	if (size > 0) {
		struct target_msg_msn *msg = malloc(sizeof(struct target_msg_msn));
		memset(msg, 0, sizeof(struct target_msg_msn));
		msg->tot_len = size;
		msg->cur_len = 0;
		msg->payload_type = msn_payload_type_ignore;
		cp->msg[cp->curdir] = msg;
	}

	return POM_OK;
}

// Retrive your contacts via SOAP, then tell the servers what are your contact
int target_msn_handler_adl(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *adl = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	int size = 0;

	char *str, *token, *saveptr = NULL;
	for (str = adl; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				break;
			case 1:	
				if (!memcmp(token, "OK", 2)) {
					target_msn_set_connection_direction(cp, f->ce->direction, 1);
				} else if (sscanf(token, "%u", &size) != 1) {
					pom_log(POM_LOG_DEBUG "ADL Invalid size received or network ID : %s", token);
					return POM_OK;
				}
				break;
		}
		token_id++;

	}

	if (size > 0) {
		struct target_msg_msn *msg = malloc(sizeof(struct target_msg_msn));
		memset(msg, 0, sizeof(struct target_msg_msn));
		msg->tot_len = size;
		msg->cur_len = 0;
		msg->payload_type = msn_payload_type_ignore;
		cp->msg[cp->curdir] = msg;
	}

	return POM_OK;
}

// Remove ppl from my list
int target_msn_handler_rml(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *rml = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	int size = 0;

	char *str, *token, *saveptr = NULL;
	for (str = rml; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				break;
			case 1:	
				if (!memcmp(token, "OK", 2)) {
					target_msn_set_connection_direction(cp, f->ce->direction, 1);
				} else if (sscanf(token, "%u", &size) != 1) {
					pom_log(POM_LOG_DEBUG "RML Invalid size received or network ID : %s", token);
					return POM_OK;
				}
				break;
		}
		token_id++;

	}

	if (size > 0) {
		struct target_msg_msn *msg = malloc(sizeof(struct target_msg_msn));
		memset(msg, 0, sizeof(struct target_msg_msn));
		msg->tot_len = size;
		msg->cur_len = 0;
		msg->payload_type = msn_payload_type_ignore;
		cp->msg[cp->curdir] = msg;
	}

	return POM_OK;
}

// Server may not be sure if user is online ... So this command is there to ask user if he is online
int target_msn_handler_fqy(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *fqy = cp->buffer[cp->curdir] + 4;

	int token_id = 0;

	int size = 0;

	char *str, *token, *saveptr = NULL;
	for (str = fqy; ; str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (!token)
			break;
		if (!strlen(token))
			continue;
		
		switch (token_id) {
			case 0:
				break;
			case 1:	
				if (sscanf(token, "%u", &size) != 1) {
					pom_log(POM_LOG_DEBUG "FQY Invalid size received or network ID : %s", token);
					return POM_OK;
				}
				break;
		}
		token_id++;

	}

	if (size > 0) {
		struct target_msg_msn *msg = malloc(sizeof(struct target_msg_msn));
		memset(msg, 0, sizeof(struct target_msg_msn));
		msg->tot_len = size;
		msg->cur_len = 0;
		msg->payload_type = msn_payload_type_ignore;
		cp->msg[cp->curdir] = msg;
	}

	return POM_OK;
}

int target_close_connection_msn(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx", (unsigned long) conntrack_priv);

	struct target_conntrack_priv_msn *cp;
	cp = conntrack_priv;

	if (cp->buffer[0])
		free(cp->buffer[0]);
	if (cp->buffer[1])
		free(cp->buffer[1]);

	cp->session->refcount--;
	if (!cp->session->refcount) {

		// Let's write everything down
		target_msn_session_save(t, cp);

		struct target_buddy_msn *bud = cp->session->buddies;
		while (bud) {
			free(bud->account);
			free(bud->nick);
			cp->session->buddies = cp->session->buddies->next;
			free(bud);
			bud = cp->session->buddies;
		}

		struct target_buddy_group_msn *grp = cp->session->groups;
		while (grp) {
			free(grp->name);
			free(grp->id);
			cp->session->groups = cp->session->groups->next;
			free(grp);
			grp = cp->session->groups;
		}
		if (cp->session->account)
			free(cp->session->account);
		free(cp->session);
	}

	if (cp->parsed_path)
		free(cp->parsed_path);


	while (cp->file) {
		struct target_file_transfer_msn *file = cp->file;
		cp->file = cp->file->next;
		free(file);
	}

	
	while (cp->parts) {
		struct target_connection_party_msn *tmp = cp->parts;
		cp->parts = tmp->next;
		free(tmp->account);
		if (tmp->nick)
			free(tmp->nick);
		free(tmp);
	}

	while (cp->conv_buff) {
		struct target_conv_event_msn *tmp = cp->conv_buff;
		cp->conv_buff = tmp->next;
		if (tmp->buff)
			free(tmp->buff);
		if (tmp->from)
			free(tmp->from);
		free(tmp);
		pom_log(POM_LOG_TSHOOT "Dropped buffered message because account wasn't found");
	}

	target_free_msg_msn(cp, 0);
	target_free_msg_msn(cp, 1);

	if (cp->fd != -1)
		close(cp->fd);

	struct target_priv_msn *priv = t->target_priv;

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;

	free(cp);

	return POM_OK;

}

int target_msn_set_connection_direction(struct target_conntrack_priv_msn *cp, unsigned int direction, int is_server_dir) {

	if (is_server_dir) {
		if (cp->server_dir == CE_DIR_UNK) {
			cp->server_dir = direction;
		} else if (cp->server_dir != direction) {
			pom_log(POM_LOG_DEBUG "Protocol direction missmatch");
			return POM_ERR;
		}
	} else {
		if (cp->server_dir == CE_DIR_UNK) {
			if (direction == CE_DIR_FWD)
				cp->server_dir = CE_DIR_REV;
			else
				cp->server_dir = CE_DIR_FWD;
		} else {
			if ((direction == CE_DIR_FWD && cp->server_dir != CE_DIR_REV) || (direction == CE_DIR_REV && cp->server_dir != CE_DIR_FWD)) {
				pom_log(POM_LOG_DEBUG "Protocol direction missmatch");
				return POM_ERR;
			}
		}
	}
	
	return POM_OK;

}


struct target_conntrack_priv_msn* target_msn_conntrack_priv_fork(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	// New connection

	char tmp[NAME_MAX + 1];
	memset(tmp, 0, sizeof(tmp));

	struct target_priv_msn *priv = t->target_priv;

	if (layer_field_parse(f->l, PTYPE_STRING_GETVAL(priv->path), tmp, NAME_MAX) == POM_ERR) {
		pom_log(POM_LOG_WARN "Error while parsing the path");
		return NULL;
	}
	struct target_conntrack_priv_msn *new_cp = NULL;
	new_cp = malloc(sizeof(struct target_conntrack_priv_msn));
	memset(new_cp, 0, sizeof(struct target_conntrack_priv_msn));
	new_cp->parsed_path = malloc(strlen(tmp) + 3);
	strcpy(new_cp->parsed_path, tmp);
	if (*(new_cp->parsed_path + strlen(new_cp->parsed_path) - 1) != '/')
		strcat(new_cp->parsed_path, "/");

	new_cp->server_dir = CE_DIR_UNK;

	cp->session->refcount++;
	new_cp->session = cp->session;

	new_cp->fd = -1;

	new_cp->next = priv->ct_privs;
	if (priv->ct_privs)
		priv->ct_privs->prev = new_cp;
	priv->ct_privs = new_cp;

	return new_cp;
}

int target_msn_add_expectation(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, char *address) {


	char * port = NULL;
	port = strchr(address, ':');
	if (!port) {
		pom_log(POM_LOG_INFO "Invalid address given : %s", address);
		return POM_ERR;
	}
	*port = 0;
	port++;

	int p = 0;
	if (sscanf(port, "%u", &p) != 1) {
		pom_log(POM_LOG_INFO "Invalid port given : %s", port);
		return POM_ERR;
	}

	struct in_addr addr;
	if (!inet_aton(address, &addr)) {
		pom_log(POM_LOG_INFO "Invalid address given : %s", address);
		return POM_ERR;
	}



	// Compute an expectation for the new connection
	struct expectation_list *expt  = expectation_alloc(f, t, f->ce, EXPT_DIR_BOTH);

	// We got a copy of our current packet
	// Source port should be same (1863) or changed to given value
	// Destination port should be ignored
	// Source ip should be changed to address
	// Destination ip should be ignored
	
	int ipv4_type = match_get_type("ipv4");
	int tcp_type = match_get_type("tcp");

	struct expectation_node *n = expt->n;
	while (n) {
		struct expectation_field *fld = n->fields;

		if (n->layer == ipv4_type) {
			while (fld) {
				if (!strcmp(fld->name, "src")) {
					PTYPE_IPV4_SETADDR(fld->value, addr);
				} 
				fld = fld->next;
			}
		} else if (n->layer == tcp_type) {
			while (fld) {
				if (!strcmp(fld->name, "sport")) {
					PTYPE_UINT16_SETVAL(fld->value, p);
				} else if (!strcmp(fld->name, "dport")) {
					fld->op = EXPT_OP_IGNORE;
				}
				fld = fld->next;
			}
		}

		n = n->next;
	}

	expectation_set_target_priv(expt, cp, target_close_connection_msn);
	if (expectation_add(expt, MSN_EXPECTATION_TIMER) == POM_ERR) {
		cp->session->refcount--;
		free(cp->parsed_path);
		free(cp);
		return POM_ERR;
	}

	pom_log(POM_LOG_TSHOOT "Expectation added for address %s:%s", address, port);
	return POM_OK;
}


int target_free_msg_msn(struct target_conntrack_priv_msn *cp, int dir) {
	
	struct target_msg_msn *m = cp->msg[dir];

	if (!m)
		return POM_OK;

	if (m->from)
		free(m->from);
	
	free(m);
	cp->msg[dir] = NULL;

	return POM_OK;
}

