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
	{ "SDG", target_msn_handler_sdg },
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
	{ "ADD", target_msn_handler_add },
	{ "DEL", target_msn_handler_del },
	{ "ADC", target_msn_handler_adc },
	{ "REM", target_msn_handler_rem },
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
	r->open = target_open_msn;
	r->process = target_process_msn;
	r->close = target_close_msn;
	r->cleanup = target_cleanup_msn;

	match_undefined_id = match_register("undefined");

	mode_default = target_register_mode(r->type, "dump", "Dump msn conversation and files");

	if (!mode_default)
		return POM_ERR;

	target_register_param(mode_default, "path", "/tmp", "Path were to dump files");
	target_register_param(mode_default, "dump_session", "yes", "Dump session information");
	target_register_param(mode_default, "dump_avatar", "yes", "Dump users avatar");
	target_register_param(mode_default, "dump_file_transfer", "no", "Dump transfered files");


	return POM_OK;

}

int target_init_msn(struct target *t) {

	struct target_priv_msn *priv = malloc(sizeof(struct target_priv_msn));
	memset(priv, 0, sizeof(struct target_priv_msn));

	t->target_priv = priv;

	priv->path = ptype_alloc("string", NULL);
	priv->dump_session = ptype_alloc("bool", NULL);
	priv->dump_avatar = ptype_alloc("bool", NULL);
	priv->dump_file_transfer = ptype_alloc("bool", NULL);

	if (!priv->path || !priv->dump_session || !priv->dump_avatar || !priv->dump_file_transfer) {
		target_cleanup_msn(t);
		return POM_ERR;
	}

	target_register_param_value(t, mode_default, "path", priv->path);
	target_register_param_value(t, mode_default, "dump_session", priv->dump_session);
	target_register_param_value(t, mode_default, "dump_avatar", priv->dump_avatar);
	target_register_param_value(t, mode_default, "dump_file_transfer", priv->dump_file_transfer);

	priv->perf_tot_conn = perf_add_item(t->perfs, "tot_conn", perf_item_type_counter, "Total number of connections handled");
	priv->perf_cur_conn = perf_add_item(t->perfs, "cur_conn", perf_item_type_gauge, "Current number of connections being handled");
	priv->perf_cur_sess = perf_add_item(t->perfs, "cur_sess", perf_item_type_gauge, "Current number of MSN sessions being handled");
	priv->perf_cur_conv = perf_add_item(t->perfs, "cur_conv", perf_item_type_gauge, "Current number of MSN conversations being handled");
	priv->perf_cur_buddies = perf_add_item(t->perfs, "cur_buddies", perf_item_type_gauge, "Current number of MSN buddies known");
	priv->perf_tot_files = perf_add_item(t->perfs, "tot_files", perf_item_type_counter, "Total number of dumped files from MSN file transfer");
	priv->perf_partial_files = perf_add_item(t->perfs, "partial_files", perf_item_type_counter, "Number of dumped files for which we only have partial content");
	priv->perf_cur_files = perf_add_item(t->perfs, "cur_files", perf_item_type_gauge, "Current number of files open from MSN file transfer");
	priv->perf_tot_msn_cmds = perf_add_item(t->perfs, "tot_msn_cmds", perf_item_type_counter, "Total number of MSN commands processed");
	priv->perf_unk_msn_cmds = perf_add_item(t->perfs, "unk_msn_cmds", perf_item_type_counter, "Total number of unknown MSN commands seen");
	priv->perf_tot_msgs = perf_add_item(t->perfs, "tot_msgs", perf_item_type_counter, "Total number of messages parsed");
	priv->perf_dropped_msgs = perf_add_item(t->perfs, "dropped_msgs", perf_item_type_counter, "Number of messages dropped because of lack of information about the session");
	priv->perf_tot_evts = perf_add_item(t->perfs, "tot_evts", perf_item_type_counter, "Total number of MSN events seen");
	priv->perf_dropped_evts = perf_add_item(t->perfs, "dropped_evts", perf_item_type_counter, "Number of dropped MSN events because of lack of information about the session");
	

	return POM_OK;
}

int target_open_msn(struct target *t) {

	return target_msn_session_init_buddy_table(t);
}

int target_close_msn(struct target *t) {

	struct target_priv_msn *priv = t->target_priv;

	while (priv->ct_privs) {
		conntrack_remove_target_priv(priv->ct_privs, priv->ct_privs->ce);
		target_close_connection_msn(t, priv->ct_privs->ce, priv->ct_privs);
	}

	int i;
	for (i = 0; i < TARGET_MSN_BUDDY_TABLE_SIZE; i++) {
		struct target_buddy_list_msn *tmp = priv->buddy_table[i];
		while (tmp) {
			struct target_buddy_msn *bud = tmp->bud;
			free(bud->account);
			if (bud->nick)
				free(bud->nick);
			if (bud->psm)
				free(bud->psm);
			free(bud);
			priv->buddy_table[i] = tmp->next;
			free(tmp);
			tmp = priv->buddy_table[i];
			perf_item_val_inc(priv->perf_cur_buddies, -1);
		}
	}

	return POM_OK;
}

int target_cleanup_msn(struct target *t) {

	struct target_priv_msn *priv = t->target_priv;

	if (priv) {
			
		ptype_cleanup(priv->path);
		ptype_cleanup(priv->dump_session);
		ptype_cleanup(priv->dump_avatar);
		ptype_cleanup(priv->dump_file_transfer);

		perf_remove_item(t->perfs, priv->perf_tot_conn);
		perf_remove_item(t->perfs, priv->perf_cur_conn);
		perf_remove_item(t->perfs, priv->perf_cur_sess);
		perf_remove_item(t->perfs, priv->perf_cur_conv);
		perf_remove_item(t->perfs, priv->perf_cur_buddies);
		perf_remove_item(t->perfs, priv->perf_tot_files);
		perf_remove_item(t->perfs, priv->perf_partial_files);
		perf_remove_item(t->perfs, priv->perf_cur_files);
		perf_remove_item(t->perfs, priv->perf_tot_msn_cmds);
		perf_remove_item(t->perfs, priv->perf_unk_msn_cmds);
		perf_remove_item(t->perfs, priv->perf_tot_msgs);
		perf_remove_item(t->perfs, priv->perf_dropped_msgs);
		perf_remove_item(t->perfs, priv->perf_tot_evts);
		perf_remove_item(t->perfs, priv->perf_dropped_evts);

		free(priv->buddy_table);
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

		cp = malloc(sizeof(struct target_conntrack_priv_msn));
		memset(cp, 0, sizeof(struct target_conntrack_priv_msn));

		cp->target_priv = priv;
		cp->server_dir = CE_DIR_UNK;
		conntrack_add_target_priv(cp, t, f->ce, target_close_connection_msn);

		// Allocate a new session
		struct target_session_priv_msn *sess;
		sess = malloc(sizeof(struct target_session_priv_msn));
		memset(sess, 0, sizeof(struct target_session_priv_msn));
		sess->fd = -1;
		sess->refcount++;
		sess->target_priv = priv;

		// Create a new empty user
		sess->user = malloc(sizeof(struct target_buddy_msn));
		memset(sess->user, 0, sizeof(struct target_buddy_msn));

		char tmp[NAME_MAX + 1];
		memset(tmp, 0, sizeof(tmp));
		if (layer_field_parse(f->l, &f->tv, PTYPE_STRING_GETVAL(priv->path), tmp, NAME_MAX) == POM_ERR) {
			pom_log(POM_LOG_WARN "Error while parsing the path");
			return POM_ERR;
		}
		sess->parsed_path = malloc(strlen(tmp) + 3);
		strcpy(sess->parsed_path, tmp);
		if (*(sess->parsed_path + strlen(sess->parsed_path) - 1) != '/')
			strcat(sess->parsed_path, "/");

		// Add the new session event
		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.from = sess->user;
		evt.type = msn_evt_session_start;
		evt.sess = sess;
		target_msn_session_event(&evt);

		cp->session = sess;
		
		sess->next = priv->sessions;
		if (priv->sessions)
			priv->sessions->prev = sess;
		priv->sessions = sess;

		cp->next = priv->ct_privs;
		if (priv->ct_privs)
			priv->ct_privs->prev = cp;
		priv->ct_privs = cp;


		// Increment the counters
		perf_item_val_inc(priv->perf_cur_conn, 1);
		perf_item_val_inc(priv->perf_tot_conn, 1);
		perf_item_val_inc(priv->perf_cur_sess, 1);

	}

	if (!cp->ce)
		cp->ce = f->ce;

	if (cp->flags & MSN_CONN_FLAG_INVALID) // Ignore packets from invalid connections
		return POM_OK;

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

		if ((cp->flags & MSN_CONN_FLAG_P2P) && !msg) {
			uint32_t len = 0;
			if (cp->flags & MSN_CONN_FLAG_UDP) {
				if (plen < sizeof(struct msn_udp_frame_layer_hdr)) {
					pom_log(POM_LOG_DEBUG "UDP frame too short to contain a valid header");
					return POM_OK;
				}
				//struct msn_udp_frame_layer_hdr *frame_hdr = (struct msn_udp_frame_layer_hdr*)(payload);
				payload += sizeof(struct msn_udp_frame_layer_hdr);
				plen -= sizeof(struct msn_udp_frame_layer_hdr);
				len = plen;

				pom_log(POM_LOG_TSHOOT "P2P binary message : len : %u", len);


			} else {
				if (plen < sizeof(struct msn_tcp_frame_layer_hdr)) {
					pom_log(POM_LOG_DEBUG "Frame too short to contain a valid header");
					return POM_OK;
				}
				struct msn_tcp_frame_layer_hdr *frame_hdr = (struct msn_tcp_frame_layer_hdr*)(payload);
				len = le32(frame_hdr->len);
				payload += sizeof(struct msn_tcp_frame_layer_hdr);
				plen -= sizeof(struct msn_tcp_frame_layer_hdr);

				pom_log(POM_LOG_TSHOOT "P2P binary message : len : %u", len);
				if (len > 2048) { // The limit seems to be 1400 actually
					pom_log(POM_LOG_DEBUG "Data length too big in P2P message : %u", len);
					return POM_OK;
				}

			}
			if (len == 0)
				continue;

			cp->msg[cp->curdir] = msn_cmd_alloc_msg(len, msn_payload_type_p2p);
			msg = cp->msg[cp->curdir];
			msg->payload_type = msn_payload_type_p2p;

		}
		if ((cp->flags & MSN_CONN_FLAG_STUN) && !msg) {
			// Check for SSL messages (actually initial handshake only)
			char ssl_hdr[3] = { 0x16, 0x03, 0x01 };// handshake, tls v1
			if (plen > 5 && !memcmp(payload, ssl_hdr, 3)) {
				uint16_t len = ntohs(*((uint16_t*) (payload + 3)));

				if (len <= plen - 5) {
					plen -= (len + 5);
					payload += (len + 5);
				}
				if (!plen)
					return POM_OK;
			}

			// Check for the STUN allocate/deallocate message
			// STUN packet is code(2), length(2), transaction(16), attributes (TLV)

			// code is either 0x0003, 0x0103 in TURN or 0x0001, 0x0101 in STUN
			if (plen > 20 // Minimum length
				&& ((payload[0] & 0x7f) == 0x0 || (payload[0] & 0x7f) == 0x01) // Client/server
				&& ((payload[1] == 0x3) || payload[1] == 0x1)) { // TURN draft/ STUN RFC allocation
				uint16_t stun_len = ntohs(*((uint16_t*) (payload + 2)));
				if (stun_len <= plen - 20)
					return POM_OK; // Ignore STUN message
			}

			if (payload[0] == 0x18 && payload[1] == 0x00)
				return POM_OK; // Ignore this for now

			if (plen < sizeof(struct msn_stun_frame_layer_hdr)) {
				pom_log(POM_LOG_DEBUG "Frame too short to contain a valid header");
				return POM_OK;
			}
			struct msn_stun_frame_layer_hdr *frame_hdr = (struct msn_stun_frame_layer_hdr*)(payload);
			uint32_t len = le32(frame_hdr->len);
			payload += sizeof(struct msn_stun_frame_layer_hdr);
			plen -= sizeof(struct msn_stun_frame_layer_hdr);

			pom_log(POM_LOG_TSHOOT "P2P binary message : len : %u", len);
			if (len > 2048) { // The limit seems to be 1400 actually
				pom_log(POM_LOG_DEBUG "Data length too big in P2P message : %u", len);
				return POM_OK;
			}

			if (len == 0)
				continue;

			cp->msg[cp->curdir] = msn_cmd_alloc_msg(len, msn_payload_type_p2p);
			msg = cp->msg[cp->curdir];
			msg->payload_type = msn_payload_type_p2p;

		}
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

		// MSNP21 doesn't use one connection per conversation
		// We have to make sure that a conversation is not associated
		// to this connection. The right conversation will be found
		// while processing the message.

		if (cp->flags & MSN_CONN_FLAG_NOSB)
			cp->conv = NULL;

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
				case msn_payload_type_msg_oob:
					res = target_process_msg_msn(t, cp, f);
					cp->conv = NULL; // Make sure conversation isn't assigned for out of band messages
					break;
				case msn_payload_type_nfy_put:
					res = target_process_nfy_put_msn(t, cp, f);
					break;
				case msn_payload_type_nfy_del:
					res = target_process_nfy_del_msn(t, cp, f);
					break;
				case msn_payload_type_sdg:
					res = target_process_sdg_msn(t, cp, f);
					break;
				case msn_payload_type_mail_invite:
					res = target_process_mail_invite_msn(t, cp, f);
					break;
				case msn_payload_type_status_msg:
					res = target_process_status_msg_msn(t, cp, f);
					break;
				case msn_payload_type_adl:
					res = target_process_adl_msn(t, cp, f);
					break;
				case msn_payload_type_sip_msg:
					res = target_process_sip_msn(t, cp, f, NULL, NULL, 0);
					target_free_msg_msn(cp, cp->curdir);
					break;
				case msn_payload_type_uun_ubn:
					res = target_process_uun_ubn_msn(t, cp, f);
					break;
				case msn_payload_type_p2p:
					res = target_process_bin_p2p_msg(t, cp, f, NULL, NULL);
					target_free_msg_msn(cp, cp->curdir);
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

	struct target_priv_msn *priv = t->target_priv;

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
			cp->flags |= MSN_CONN_FLAG_INVALID;
			return POM_OK;
		}

		pom_log(POM_LOG_DEBUG "Unhandled command %3s", cp->buffer[cp->curdir]);
		perf_item_val_inc(priv->perf_unk_msn_cmds, 1);
		return POM_OK;
	}

	perf_item_val_inc(priv->perf_tot_msn_cmds, 1);

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

	int i;
	for (i = 0; i <= 1; i++) {
		if (cp->buffer[i])
			free(cp->buffer[i]);
		target_free_msg_msn(cp, i);
		if (cp->sip_msg_buff[i]) {
			if (cp->sip_msg_buff[i]->buffer)
				free(cp->sip_msg_buff[i]->buffer);
			free(cp->sip_msg_buff[i]);
		}
	}


	struct target_session_priv_msn *sess = cp->session;
	struct target_conversation_msn *conv = cp->conv;

	sess->refcount--;

	// Close files before the conversation gets closed
	if (!sess->refcount) {
		while (sess->file) {
			target_session_close_file_msn(priv, sess->file);
		}
	}

	if (conv) {
		conv->refcount--;
		if (!conv->refcount) {
			struct target_file_transfer_msn *file = sess->file;
			while (file) {
				if (file->conv == conv) {
					struct target_file_transfer_msn *tmp_file = file;
					file = file->next;
					target_session_close_file_msn(priv, tmp_file);
					continue;
				}
				file = file->next;
			}
			while (conv->parts) {
				struct target_connection_party_msn *tmp = conv->parts;
				conv->parts = tmp->next;
				free(tmp);
			}

			while (conv->evt_buff) {
				struct target_event_msn *tmp = conv->evt_buff;
				conv->evt_buff = tmp->next;
				if (tmp->buff)
					free(tmp->buff);
				if (tmp->type == msn_evt_message) {
					perf_item_val_inc(priv->perf_tot_msgs, 1);
					perf_item_val_inc(priv->perf_dropped_msgs, 1);
				}
				free(tmp);
				pom_log(POM_LOG_TSHOOT "Dropped buffered message because account wasn't found");
				perf_item_val_inc(priv->perf_tot_evts, 1);
				perf_item_val_inc(priv->perf_dropped_evts, 1);
			}

			if (conv->fd != -1)
				close(conv->fd);

			if (conv->next)
				conv->next->prev = conv->prev;
			
			if (conv->prev)
				conv->prev->next = conv->next;
			else
				sess->conv = conv->next;

			free(conv);

			perf_item_val_inc(priv->perf_cur_conv, -1);
		}

	}

	if (!sess->refcount) {

		if (sess->fd != -1) {
			target_msn_session_dump_buddy_list(cp);
			close(sess->fd);
		}

		struct target_buddy_list_session_msn *bud_lst = sess->buddies;
		while (bud_lst) {
			sess->buddies = sess->buddies->next;

			struct target_buddy_msn *bud = bud_lst->bud;
			struct target_session_list_msn *prev_sess_lst = NULL, *sess_lst = bud_lst->bud->sess_lst;
			while (sess_lst) {
				if (sess_lst->sess == sess) {
					if (!prev_sess_lst)
						bud_lst->bud->sess_lst = sess_lst->next;
					else
						prev_sess_lst->next = sess_lst->next;
					free(sess_lst);
					break;
				}
				prev_sess_lst = sess_lst;
				sess_lst = sess_lst->next;
			}

			free(bud_lst);
			bud_lst = sess->buddies;

			// Buddy doesn't belong to any session, remove it from the hash table
			if (!bud->sess_lst) {
				uint32_t hash = target_msn_session_get_buddy_hash(bud->account);
				struct target_buddy_list_msn *bud_hash_lst = priv->buddy_table[hash], *prev_bud_hash_lst = NULL;
				while (bud_hash_lst && bud_hash_lst->bud != bud) {
					prev_bud_hash_lst = bud_hash_lst;
					bud_hash_lst = bud_hash_lst->next;
				}

				if (!bud_hash_lst) {
					pom_log(POM_LOG_WARN "Buddy not found while looking for it in the hash table");
				} else {
					if (prev_bud_hash_lst)
						prev_bud_hash_lst->next = bud_hash_lst->next;
					else
						priv->buddy_table[hash] = bud_hash_lst->next;

					free(bud->account);
					if (bud->nick)
						free(bud->nick);
					if (bud->psm)
						free(bud->psm);
					free(bud);
					free(bud_hash_lst);

					perf_item_val_inc(priv->perf_cur_buddies, -1);
				}
				
			}
		}

		while (sess->conv) {
			conv = sess->conv;
			if (!conv->refcount) {
				pom_log(POM_LOG_DEBUG "Warning, conversation refcount is not 0");
				sess->conv = conv->next;
				continue;
			}

			while (conv->parts) {
				struct target_connection_party_msn *tmp = conv->parts;
				conv->parts = tmp->next;
				free(tmp);
			}

			while (conv->evt_buff) {
				struct target_event_msn *tmp = conv->evt_buff;
				conv->evt_buff = tmp->next;
				if (tmp->buff)
					free(tmp->buff);
				
				if (tmp->type == msn_evt_message) {
					perf_item_val_inc(priv->perf_tot_msgs, 1);
					perf_item_val_inc(priv->perf_dropped_msgs, 1);
				}

				free(tmp);
				pom_log(POM_LOG_TSHOOT "Dropped buffered message because account wasn't found");
				perf_item_val_inc(priv->perf_tot_evts, 1);
				perf_item_val_inc(priv->perf_dropped_evts, 1);
			}

			if (conv->fd != -1)
				close(conv->fd);

			sess->conv = conv->next;
			free(conv);
			perf_item_val_inc(priv->perf_cur_conv, -1);

		}

		while (sess->evt_buff) {
			struct target_event_msn *tmp = sess->evt_buff;
			sess->evt_buff = tmp->next;
			if (tmp->buff)
				free(tmp->buff);
			free(tmp);
			pom_log(POM_LOG_TSHOOT "Dropped buffered event because account wasn't found");
			perf_item_val_inc(priv->perf_tot_evts, 1);
			perf_item_val_inc(priv->perf_dropped_evts, 1);
		}

		// Remove session reference from the account
		struct target_session_list_msn *prev_sess_lst = NULL, *sess_lst = sess->user->sess_lst;
		while (sess_lst) {
			if (sess_lst->sess == sess) {
				if (!prev_sess_lst)
					sess->user->sess_lst = sess_lst->next;
				else
					prev_sess_lst->next = sess_lst->next;
				free(sess_lst);
				break;
			}
			prev_sess_lst = sess_lst;
			sess_lst = sess_lst->next;
		}

		if (sess->parsed_path)
			free(sess->parsed_path);

		if (sess->next)
			sess->next->prev = sess->prev;
		if (sess->prev)
			sess->prev->next = sess->next;

		if (sess == priv->sessions) 
			priv->sessions = sess->next;

		if (!sess->user->account) { // Account not populated, it's a temporary buddy
			if (sess->user->nick)
				free(sess->user->nick);
			if (sess->user->psm)
				free(sess->user->psm);
			free(sess->user);
		}

		free(sess);

		perf_item_val_inc(priv->perf_cur_sess, -1);
	}



	if (cp->prev)
		cp->prev->next = cp->next;
	else
		priv->ct_privs = cp->next;

	if (cp->next)
		cp->next->prev = cp->prev;

	free(cp);

	perf_item_val_inc(priv->perf_cur_conn, -1);

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

	struct target_priv_msn *priv = t->target_priv;

	struct target_conntrack_priv_msn *new_cp = NULL;
	new_cp = malloc(sizeof(struct target_conntrack_priv_msn));
	memset(new_cp, 0, sizeof(struct target_conntrack_priv_msn));

	new_cp->target_priv = t->target_priv;
	new_cp->server_dir = CE_DIR_UNK;

	cp->session->refcount++;
	new_cp->session = cp->session;

	new_cp->next = priv->ct_privs;
	if (priv->ct_privs)
		priv->ct_privs->prev = new_cp;
	priv->ct_privs = new_cp;

	perf_item_val_inc(priv->perf_cur_conn, 1);
	perf_item_val_inc(priv->perf_tot_conn, 1);

	return new_cp;
}

int target_add_expectation_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, char *address, char *port, unsigned int flags) {

	struct target_priv_msn *priv = t->target_priv;

	// Create an expectation for the new connection
	struct expectation_list *expt  = expectation_alloc(t, f->ce, f->input, EXPT_DIR_BOTH);
	
	struct expectation_node *l3 = NULL, *l4 = NULL;

	if (strchr(address, ':')) { // Check for IPv6 or IPv4
		l3 = expectation_add_layer(expt, match_get_type("ipv6"));
	} else {
		l3 = expectation_add_layer(expt, match_get_type("ipv4"));
	}

	if (flags & MSN_CONN_FLAG_UDP) { // Check for UDP or TCP
		l4 = expectation_add_layer(expt, match_get_type("udp"));
	} else {
		l4 = expectation_add_layer(expt, match_get_type("tcp"));
	}

	if (!l3 || !l4) {
		pom_log(POM_LOG_WARN "Unable to create expectation");
		expectation_cleanup(expt);
		return POM_ERR;
	}

	if (expectation_layer_set_field(l3, "dst", address, PTYPE_OP_EQ) != POM_OK) {
		pom_log(POM_LOG_DEBUG "Invalid address given to create an expectation : %s", address);
		expectation_cleanup(expt);
		return POM_ERR;
	}
	if (expectation_layer_set_field(l4, "dport", port, PTYPE_OP_EQ) != POM_OK) {
		pom_log(POM_LOG_DEBUG "Invalid port given to create an expectation : %s", port);
		expectation_cleanup(expt);
		return POM_ERR;
	}

	struct target_conntrack_priv_msn *new_cp = target_msn_conntrack_priv_fork(t, cp, f);
	new_cp->flags = flags;

	if (!(flags & MSN_CONN_FLAG_OOB) && cp->conv) {
		cp->conv->refcount++;
		new_cp->conv = cp->conv;
	}


	expectation_set_target_priv(expt, new_cp, target_close_connection_msn);
	if (expectation_add(expt, MSN_EXPECTATION_TIMER) == POM_ERR) {
		pom_log(POM_LOG_WARN "Unable to add an expectation");
		new_cp->session->refcount--;
		free(new_cp);
		perf_item_val_inc(priv->perf_cur_conn, -1);
		return POM_ERR;
	}

	pom_log(POM_LOG_TSHOOT "Expectation added for destination %s:%s", address, port);
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
