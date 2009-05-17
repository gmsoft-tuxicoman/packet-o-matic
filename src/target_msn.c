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


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include "target_msn.h"
#include "target_msn_cmds.h"
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
	{ "UUM", target_msn_handler_uum },
	{ "UBM", target_msn_handler_ubm },
	{ "PRP", target_msn_handler_prp },
	{ "LSG", target_msn_handler_lsg },
	{ "LST", target_msn_handler_lst },
	{ "CHG", target_msn_handler_chg },
	{ "PNG", target_msn_handler_png },
	{ "QNG", target_msn_handler_qng },
	{ "UBX", target_msn_handler_ubx },
	{ "UBN", target_msn_handler_ubn },
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
	{ "SDC", target_msn_handler_sdc },
	{ "SND", target_msn_handler_snd },
	{ "QRY", target_msn_handler_qry },
	{ "REA", target_msn_handler_rea },
	{ "NFY", target_msn_handler_nfy },
	{ "PUT", target_msn_handler_put },
	{ "SBS", target_msn_handler_ignore },
	{ "SBP", target_msn_handler_ignore },
	{ "BLP", target_msn_handler_ignore },
	{ "CHL", target_msn_handler_ignore },
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

		// Allocate a new session
		struct target_session_priv_msn *sess;
		sess = malloc(sizeof(struct target_session_priv_msn));
		memset(sess, 0, sizeof(struct target_session_priv_msn));
		sess->fd = -1;
		sess->refcount++;
		cp->session = sess;
		
		sess->next = priv->sessions;
		if (priv->sessions)
			priv->sessions->prev = sess;
		priv->sessions = sess;

		cp->fd = -1;

		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;


	}

	if (!cp->ce)
		cp->ce = f->ce;

	if (cp->is_invalid) // Ignore packets from invalid connections
		return POM_OK;

	// Split in lines
	char *payload = f->buff + lastl->payload_start;
	unsigned int plen = lastl->payload_size;

	while (plen > 0) {

		if (cp->is_invalid) // Don't continue to process if it was marked invalid
			return POM_OK;

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
				end = strchr(cp->buffer[dir], '\n');

			if (!end) { // Nothing was found let's look into our payload
				unsigned int len = 0, full_len;
				end = memchr(payload, '\n', plen);
				if (end) {
					len = end - payload;
					full_len = len + 1;
					if (*(end - 1) == '\r')
						len--;
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
					int bufflen = len;
					if (cp->buffer[dir]) {
						bufflen += strlen(cp->buffer[dir]);
					} else {
						cp->buffer[dir] = malloc(bufflen + 1);
						*cp->buffer[dir] = 0;
						cp->buffer_len[dir] = bufflen + 1;

					}
						
					if (cp->buffer_len[dir] < bufflen + 1) {
						cp->buffer[dir] = realloc(cp->buffer[dir], bufflen + 1);
						cp->buffer_len[dir] = bufflen + 1;
					}

					strncat(cp->buffer[dir], payload, len);
					plen -= full_len;
					payload += full_len;
				}
			} else {
				*end = 0;
			}
		}

		int res = POM_OK;
		if (!msg) {
			pom_log(POM_LOG_TSHOOT "Command : %s", cp->buffer[dir]);
			res = target_process_line_msn(t, cp, f);

			*cp->buffer[dir] = 0;
		} else {
			switch (msg->payload_type) {
				case msn_payload_type_msg:
					res = target_process_msg_msn(t, cp, f);
					break;
				case msn_payload_type_mail_invite:
					res = target_process_mail_invite_msn(t, cp, f);
					break;
				case msn_payload_type_status_msg:
					res = target_process_status_msg_msn(t, cp, f);
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
			return target_msn_handler_error(t, cp, f);
		}

		// Check if cmd name is at least alphanum

		int is_alnum = 1;
		for (i = 0; i < 3; i++) {
			if (!isalnum(cp->buffer[cp->curdir][i])) {
				is_alnum = 0;
				break;
			}
		}

		if (!is_alnum) {
			pom_log(POM_LOG_DEBUG "Invalid command given. Ignoring connection");
			cp->is_invalid = 1;
			return POM_OK;
		}

		pom_log(POM_LOG_DEBUG "Unhandled command %3s", cp->buffer[cp->curdir]);
		return POM_OK;
	}

	return (*handler) (t, cp, f);


}


int target_process_payload_ignore_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	struct target_msg_msn *m = cp->msg[cp->curdir];
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

int target_close_connection_msn(struct target *t, struct conntrack_entry *ce, void *conntrack_priv) {

	struct target_priv_msn *priv = t->target_priv;

	pom_log(POM_LOG_TSHOOT "Closing connection 0x%lx", (unsigned long) conntrack_priv);

	// Remove any remaining expectation
	expectation_cleanup_ce(t, ce);

	struct target_conntrack_priv_msn *cp;
	cp = conntrack_priv;

	if (cp->buffer[0])
		free(cp->buffer[0]);
	if (cp->buffer[1])
		free(cp->buffer[1]);

	struct target_session_priv_msn *sess = cp->session;

	sess->refcount--;
	if (!sess->refcount) {

		if (sess->fd != -1) {
			target_msn_session_dump_buddy_list(cp);
			close(sess->fd);
		}

		struct target_buddy_msn *bud = sess->buddies;
		while (bud) {
			free(bud->account);
			if (bud->nick)
				free(bud->nick);
			if (bud->group_list)
				free(bud->group_list);
			if (bud->psm)
				free(bud->psm);
			sess->buddies = sess->buddies->next;
			free(bud);
			bud = sess->buddies;
		}

		struct target_buddy_group_msn *grp = sess->groups;
		while (grp) {
			free(grp->name);
			free(grp->id);
			sess->groups = sess->groups->next;
			free(grp);
			grp = sess->groups;
		}
		if (sess->user.account)
			free(sess->user.account);
		if (sess->user.nick)
			free(sess->user.nick);
		if (sess->user.psm)
			free(sess->user.psm);

		if (sess->next)
			sess->next->prev = sess->prev;
		if (sess->prev)
			sess->prev->next = sess->next;

		if (sess == priv->sessions) 
			priv->sessions = sess->next;

		free(sess);
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
		free(tmp);
	}

	while (cp->conv_buff) {
		struct target_event_msn *tmp = cp->conv_buff;
		cp->conv_buff = tmp->next;
		if (tmp->buff)
			free(tmp->buff);
		free(tmp);
		pom_log(POM_LOG_TSHOOT "Dropped buffered message because account wasn't found");
	}

	target_free_msg_msn(cp, 0);
	target_free_msg_msn(cp, 1);

	if (cp->fd != -1)
		close(cp->fd);

	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;

	free(cp);

	return POM_OK;

}

int target_msn_chk_conn_dir(struct target_conntrack_priv_msn *cp, unsigned int pkt_dir, int msn_dir) {

	if (cp->server_dir == CE_DIR_UNK) {
		if (msn_dir == MSN_DIR_FROM_SERVER)
			cp->server_dir = pkt_dir;
		else {
			if (pkt_dir == CE_DIR_FWD)
				cp->server_dir = CE_DIR_REV;
			else
				cp->server_dir = CE_DIR_FWD;
		}
		return POM_OK;
	}

	if (msn_dir == MSN_DIR_FROM_SERVER) {
		if (cp->server_dir != pkt_dir) {
			pom_log(POM_LOG_DEBUG "Protocol direction missmatch");
			return POM_ERR;
		}
	} else if (cp->server_dir == MSN_DIR_FROM_CLIENT) {
		if ((pkt_dir == CE_DIR_FWD && cp->server_dir != CE_DIR_REV) || (pkt_dir == CE_DIR_REV && cp->server_dir != CE_DIR_FWD)) {
			pom_log(POM_LOG_DEBUG "Protocol direction missmatch");
			return POM_ERR;
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
	
	free(m);
	cp->msg[dir] = NULL;

	return POM_OK;
}

