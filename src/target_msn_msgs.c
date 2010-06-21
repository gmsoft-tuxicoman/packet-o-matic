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

#include "target_msn.h"
#include "target_msn_msgs.h"
#include "target_msn_session.h"

#include "ptype_bool.h"

#include <fcntl.h>
#include <libxml/parser.h>

#include <iconv.h>
#include <errno.h>
#include <stddef.h>


static struct msn_mime_type msn_mime_types[] = {
	{ "dummy/unknown", NULL },
	{ "text/plain", target_process_mime_text_plain_msg }, // Message from a user
	{ "text/x-msmsgsemailnotification", target_process_mail_notification_msn }, // User got a mail
	{ "text/x-msmsgsactivemailnotification", NULL }, // User deleted a mail or so
	{ "text/x-msmsgsprofile", target_process_msg_profile_msn }, // Initial profile
	{ "text/x-msmsgsinitialmdatanotification", NULL }, // User has offline messages
	{ "text/x-msmsgsoimnotification", NULL }, // User received an offline message
	{ "text/x-msmsgscontrol", target_process_mime_msmsgscontrol_msg }, // User is typing
	{ "application/x-msnmsgrp2p", target_process_mime_msnmsgrp2p_msg }, // File transfer
	{ "text/x-msnmsgr-datacast" , target_process_mime_datacast_msg }, // Plugin action (nudge/winks/etc)
	{ "text/x-mms-emoticon", NULL }, // Custom emoticon message sent right before the emoticon is being used
	{ "text/x-mms-animemoticon", NULL }, // Animated custom emoticon (who the hell needs emoticon anyway ?)
	{ "text/x-clientcaps", NULL }, // Sent by opensource clients to indicate if client is logging and the client name
	{ "text/x-keepalive", NULL }, // Some clients uses keepalive
	{ "text/x-msmsgsinitialemailnotification", NULL }, // Initial mail count
	{ 0, 0},
};

char* line_split(struct target_conntrack_priv_msn *cp) {

	char *line = cp->buffer[cp->curdir] + cp->msg[cp->curdir]->cur_pos;

	char *eol = memchr(line, '\n', cp->buffer_len[cp->curdir] - cp->msg[cp->curdir]->cur_pos);
	if (!eol)
		return NULL;

	unsigned int len = eol - line + 1;
	cp->msg[cp->curdir]->cur_pos += len;

	*eol = 0;
	if ((eol - 1) > cp->buffer[cp->curdir] && *(eol - 1) == '\r')
		*(eol - 1) = 0;

	return line;
}

struct msn_header *header_split(struct target_conntrack_priv_msn *cp) {

	unsigned int hdr_num = 0;
	struct msn_header *res = NULL;

	struct target_msg_msn *msg = cp->msg[cp->curdir];

	while (msg->cur_pos < msg->tot_len) {

		res = realloc(res, sizeof(struct msn_header) * (hdr_num + 1));
		memset(&res[hdr_num], 0, sizeof(struct msn_header));

		char *line = line_split(cp);
		if (!line)
			return res;

		if (!strlen(line))
			return res;

		char *arg = strchr(line, ':');
		if (!arg)
			return res;

		*arg = 0;
		do { arg++; } while (*arg == ' ');

		res[hdr_num].name = line;
		res[hdr_num].value = arg;

		hdr_num++;

	}

	res = realloc(res, sizeof(struct msn_header) * (hdr_num + 1));
	memset(&res[hdr_num], 0, sizeof(struct msn_header));

	return res;
}

int target_process_msg_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {


	struct msn_header *hdrs = header_split(cp);
	unsigned int hdr_num = 0;

	struct target_msg_msn *msg = cp->msg[cp->curdir];

	while (hdrs[hdr_num].name) {

		if (!strcasecmp(hdrs[hdr_num].name, "MIME-Version")) {
			pom_log(POM_LOG_TSHOOT "Header MIME-Version : %s", hdrs[hdr_num].value);
		} else if (!strcasecmp(hdrs[hdr_num].name, "Content-Type")) { // This should be the second header in every msg
			int id = 0;
			char *coma = strchr(hdrs[hdr_num].value, ';');
			if (coma)
				*coma = 0; // Strip the rest of the mime-type
			for (id = 0; msn_mime_types[id].name; id++) {
				if (!strcasecmp(msn_mime_types[id].name, hdrs[hdr_num].value)) {
					msg->mime_type = id;
					pom_log(POM_LOG_TSHOOT "Header Content-Type found : %s", hdrs[hdr_num].value);
					int res = POM_OK;
					if (msn_mime_types[id].handler) {
						res = (*msn_mime_types[id].handler) (t, cp, f, &hdrs[hdr_num + 1]);
					} else {
						pom_log(POM_LOG_TSHOOT "Unhandled mime-type : %s", hdrs[hdr_num].value);
					}
					// Done with the message
					target_free_msg_msn(cp, cp->curdir);
					free(hdrs);
					return res;
				}
			}
			if (!msg->mime_type)
				pom_log(POM_LOG_DEBUG "Header Content-Type unknown : %s", hdrs[hdr_num].value);
		} else if (!strcasecmp(hdrs[hdr_num].name, "Chunk") || !strcasecmp(hdrs[hdr_num].name, "Message-ID")) {
			// Headers found in winks message
			// Do nothHeaders found in winks message
			// Do nothing for now
		} else {
			pom_log(POM_LOG_DEBUG "Unhandled header : %s : %s", hdrs[hdr_num].name, hdrs[hdr_num].value);
		}

		hdr_num++;
	}


	// Done with the message
	target_free_msg_msn(cp, cp->curdir);
	free(hdrs);
	return POM_OK;

}


int target_process_mime_msmsgscontrol_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs) {

	unsigned int hdr_num = 0;

	while (hdrs[hdr_num].name) {
		if (!strcasecmp(hdrs[hdr_num].name, "TypingUser")) {
			pom_log(POM_LOG_TSHOOT "User %s is typing", hdrs[hdr_num].value);
			break;
		}

		hdr_num++;
	}

	return POM_OK;
}


int target_process_mime_text_plain_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs) {


	struct target_msg_msn *m = cp->msg[cp->curdir];

	struct target_event_msn evt;
	memset(&evt, 0, sizeof(struct target_event_msn));
	memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
	evt.from = m->from;
	evt.to = m->to;
	evt.buff = cp->buffer[cp->curdir] + m->cur_pos;
	evt.type = msn_evt_message;
	evt.conv = cp->conv;
	evt.sess = cp->session;

	int res = target_msn_session_event(&evt);
	m->cur_pos = m->tot_len;
	
	return res;
}

int target_process_mime_datacast_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs) {

	unsigned int hdr_num = 0;
	while (hdrs[hdr_num].name) {
		if (!strcasecmp(hdrs[hdr_num].name, "Chunk")) {
			// We only care about the first chunk which has the header "Chunks"
			// Subsequent packets have the header "Chunks"
			return POM_OK;
		}
		hdr_num++;
	}

	struct msn_header *action_hdrs = header_split(cp);
	unsigned int action_id = 0;
	for (hdr_num = 0; action_hdrs[hdr_num].name; hdr_num++) {
		if (!strcasecmp(action_hdrs[hdr_num].name, "ID")) {
			if (sscanf(action_hdrs[hdr_num].value, "%u", &action_id) != 1) {
				pom_log(POM_LOG_DEBUG "Unable to parse action id in datacast message : %s", action_hdrs[hdr_num].value);
				free(action_hdrs);
				return POM_OK;
			}
			break;

		}
	}
	free(action_hdrs);

	if (!action_id) {
		pom_log(POM_LOG_DEBUG "No action id found in datacast message");
		return POM_OK;
	}

	struct target_msg_msn *m = cp->msg[cp->curdir];

	struct target_event_msn evt;
	memset(&evt, 0, sizeof(struct target_event_msn));
	memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
	evt.from = m->from;
	evt.to = m->to;
	evt.buff = cp->buffer[cp->curdir] + m->cur_pos;
	evt.conv = cp->conv;
	evt.sess = cp->session;

	switch (action_id) {
		case 1: // nudge
			evt.type = msn_evt_nudge;
			break;
		case 2: // winks
			evt.type = msn_evt_wink;
			break;
		case 3: // voice clip
		case 4: // action message
		default:
			pom_log(POM_LOG_DEBUG "Unsupported action %u in datacast message", action_id);
			return POM_OK;
	}

	int res = target_msn_session_event(&evt);

	m->cur_pos = m->tot_len;

	return res;
}

int target_process_mime_msnmsgrp2p_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs) {


	struct target_msg_msn *m = cp->msg[cp->curdir];

	// Process remaining headers before the second batch of headers
	
	char *p2p_dest = NULL, *p2p_src = NULL;
	int hdr_num = 0;
	for (hdr_num = 0; hdrs[hdr_num].name; hdr_num++) {

		if (!p2p_dest && !strcasecmp(hdrs[hdr_num].name, "P2P-Dest")) {
			p2p_dest = hdrs[hdr_num].value;
		} else if (!p2p_src && !strcasecmp(hdrs[hdr_num].name, "P2P-Src"))
			p2p_src = hdrs[hdr_num].value;

	}

	struct target_buddy_msn *buddy_dest = NULL;
	char *buddy_dest_guid = NULL;

	char *p2p_dest_guid = NULL, *p2p_src_guid = NULL;;
	if (p2p_dest) {
		p2p_dest_guid = strchr(p2p_dest, ';');
		if (p2p_dest_guid)
			p2p_dest_guid++;
		if (m->from) { // Message wasn't sent by the user
			target_msn_session_found_account(t, cp, p2p_dest);
		} else {
			struct target_connection_party_msn *party_dest = target_msn_session_found_party(t, cp, p2p_dest, NULL, &f->tv);
			if (party_dest) {
				buddy_dest = party_dest->buddy;
				buddy_dest_guid = p2p_dest_guid;
			} else
				pom_log(POM_LOG_DEBUG "Invalid destination party in P2P message : %s", p2p_dest);
				
		}
	}
	
	if (p2p_src) {
		p2p_src_guid = strchr(p2p_src, ';');
		if (p2p_src_guid)
			p2p_src_guid++;
		if (m->from) { // Message wasn't sent by the user
			struct target_connection_party_msn *party_dest = target_msn_session_found_party(t, cp, p2p_src, NULL, &f->tv);
			if (party_dest) {
				buddy_dest = party_dest->buddy;
				buddy_dest_guid = p2p_src_guid;
			} else
				pom_log(POM_LOG_DEBUG "Invalid destination party in P2P message : %s", p2p_src);
		} else {
			target_msn_session_found_account(t, cp, p2p_src);
		}
	}


	if (p2p_dest_guid || p2p_src_guid) { // There are semicolons into either p2p-dest or p2p-src -> it is using the new wlm2009 binary format
		cp->flags |= MSN_CONN_FLAG_WLM2009_BIN;
	}

	return target_process_bin_p2p_msg(t, cp, f, buddy_dest, buddy_dest_guid);
}

int target_process_bin_p2p_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct target_buddy_msn *buddy_dest, char *buddy_guid) {

	struct target_priv_msn *priv = t->target_priv;

	uint32_t sess_id = 0, id = 0, msg_size = 0, flags = 0;
	uint64_t remaining_size = 0, total_size = 0;
	struct target_msg_msn *m = cp->msg[cp->curdir];
	struct target_session_priv_msn *sess = cp->session;

	if (cp->flags & MSN_CONN_FLAG_WLM2009_BIN) {

		if (cp->flags & MSN_CONN_FLAG_P2P) {
			if ((m->tot_len - m->cur_pos >= 4) && !memcmp(cp->buffer[cp->curdir] + m->cur_pos, "foo", 4)) {
				// Foo packet
				return POM_OK;
			}
			if (m->tot_len == 16) { // Nonce packet
				// It wouldn't contain data anyway since the transport and data header size is 8 bytes each min
				return POM_OK;
			}
		}

		if (m->tot_len - m->cur_pos < sizeof(struct msn_transport_layer_hdr)) {
			pom_log(POM_LOG_DEBUG "Payload too short to contain the transport layer header");
			return POM_OK;
		}
	
		struct msn_transport_layer_hdr *bin_hdr = (struct msn_transport_layer_hdr*)(cp->buffer[cp->curdir] + m->cur_pos);
		uint16_t plen = ntohs(bin_hdr->data_len);

		if (bin_hdr->hdr_len < sizeof(struct msn_transport_layer_hdr)) {
			pom_log(POM_LOG_DEBUG "Invalid header lenght in P2P transport layer header");
			return POM_OK;
		}

		if ((m->tot_len - m->cur_pos < bin_hdr->hdr_len + plen)) {
			pom_log(POM_LOG_DEBUG "Payload too short to contain the data layer");
			return POM_OK;
		}

		pom_log(POM_LOG_TSHOOT "Header len %u, opcode : %u, data_len %u", bin_hdr->hdr_len, bin_hdr->opcode, plen);


		m->cur_pos += bin_hdr->hdr_len;

		if (plen >= sizeof(struct msn_data_layer_hdr)) {

			struct msn_data_layer_hdr *data_hdr = (struct msn_data_layer_hdr*) (cp->buffer[cp->curdir] + m->cur_pos);
			if (data_hdr->hdr_len < sizeof(struct msn_data_layer_hdr)) {
				pom_log(POM_LOG_DEBUG "Invalid header lenght in P2P binary data layer header");
				return POM_OK;
			}

			sess_id = ntohl(data_hdr->session);

			plen -= data_hdr->hdr_len;
			pom_log(POM_LOG_TSHOOT "Session id : %u, payload_len : %u, opcode : 0x%x", sess_id, plen, data_hdr->opcode);

			if ((data_hdr->hdr_len > sizeof(struct msn_data_layer_hdr))
				&& (data_hdr->hdr_len - sizeof(struct msn_data_layer_hdr)) > sizeof(struct msn_tlv_hdr)) {

				char tlv_len = data_hdr->hdr_len - sizeof(struct msn_data_layer_hdr);
				struct msn_tlv_hdr *tlv_hdr = (struct msn_tlv_hdr*)(cp->buffer[cp->curdir] + m->cur_pos + sizeof(struct msn_data_layer_hdr));

				pom_log(POM_LOG_TSHOOT "TLV header found ! max len : %u, len %u, type : %u", tlv_len, tlv_hdr->len, tlv_hdr->type);

				if (tlv_hdr->type == 0x1) { // Remaining stuff in the binary message
					remaining_size = ntohll(*((uint64_t*) (cp->buffer[cp->curdir] + m->cur_pos + sizeof(struct msn_data_layer_hdr) + sizeof(struct msn_tlv_hdr))));
					
					pom_log(POM_LOG_TSHOOT "Remaining size : %llu", remaining_size);
				}

			}

			m->cur_pos += data_hdr->hdr_len;

			if (remaining_size == 0 && plen == 4) { // Discard useless data preparation
				return POM_OK;
			}

			msg_size = plen;

		} else {
			if (plen)
				pom_log(POM_LOG_TSHOOT "Transport payload too short in P2P binary message to contain a data header");
		}

	} else {


		// Parse the 48 byte binary field

		if (m->tot_len - m->cur_pos < 48) {
			pom_log(POM_LOG_DEBUG "Payload too short to contain the binary header");
			return POM_OK;
		}

		// We don't care about the ACK

		// This stupid header is in little endian
		uint64_t offset = 0;
		char *bin_hdr = cp->buffer[cp->curdir] + m->cur_pos;
		memcpy(&sess_id, bin_hdr, sizeof(sess_id)); sess_id = le32(sess_id);
		memcpy(&id, bin_hdr + 4, sizeof(id)); id = le32(id);
		memcpy(&offset, bin_hdr + 8, sizeof(offset)); offset = le64(offset);
		memcpy(&total_size, bin_hdr + 16, sizeof(total_size)); total_size = le64(total_size);
		memcpy(&msg_size, bin_hdr + 24, sizeof(msg_size)); msg_size = le32(msg_size);
		memcpy(&flags, bin_hdr + 28, sizeof(flags)); flags = le32(flags);

		m->cur_pos += 48;

		if (total_size == 4) { // Discard useless data preparation message
			return POM_OK; // Ignore this crap
		}

		if (msg_size > total_size) {
			pom_log(POM_LOG_DEBUG "Invalid msg_size or total_size : %u and %u", msg_size, total_size);
			return POM_OK;
		}

		remaining_size = total_size - offset - msg_size;
	}

	if (msg_size == 0) // Check for empty messages
		return POM_OK;



	// Find out what's next
	if (!sess_id) {
		// Session id == 0 -> must be SIP negociation
	
		if (cp->sip_msg_buff[cp->curdir]) {
			struct target_bin_msg_buff_msn *sip_msg = cp->sip_msg_buff[cp->curdir];
			if (msg_size + sip_msg->cur_pos > sip_msg->total_size) {
				pom_log(POM_LOG_DEBUG "Buffer overflow in segmented SIP message handling. Dropping");
				free(sip_msg->buffer);
				free(sip_msg);
				cp->sip_msg_buff[cp->curdir] = NULL;
				return POM_OK;
			}
			memcpy(sip_msg->buffer + sip_msg->cur_pos, cp->buffer[cp->curdir] + m->cur_pos, msg_size);
			sip_msg->cur_pos += msg_size;

			if (sip_msg->cur_pos >= sip_msg->total_size) {
				pom_log(POM_LOG_TSHOOT "Processing segmented SIP message : %u bytes", sip_msg->total_size);

				// Nasty hack to swap buffers

				char *old_cp_buffer = cp->buffer[cp->curdir];
				unsigned int old_cp_buffer_len = cp->buffer_len[cp->curdir];
				unsigned int old_msg_cur_pos = m->cur_pos;
				unsigned int old_msg_tot_len = m->tot_len;

				cp->buffer[cp->curdir] = sip_msg->buffer;
				cp->buffer_len[cp->curdir] = sip_msg->total_size + 1;
				m->cur_pos = 0;
				m->tot_len = sip_msg->total_size;
				
				int res = target_process_sip_msn(t, cp, f, buddy_dest, buddy_guid, 0);

				cp->buffer[cp->curdir] = old_cp_buffer;
				cp->buffer_len[cp->curdir] = old_cp_buffer_len;
				m->cur_pos = old_msg_cur_pos;
				m->tot_len = old_msg_tot_len;

				free(sip_msg->buffer);
				free(sip_msg);
				cp->sip_msg_buff[cp->curdir] = NULL;

				return res;

			}
		} else if (remaining_size > 0) {
			if (cp->flags & MSN_CONN_FLAG_WLM2009_BIN) // WLM2009 doesn't provide the total_size
				total_size = msg_size + remaining_size;

			if (total_size > (unsigned int)-1) { // Avoid integer overflow
				pom_log(POM_LOG_DEBUG "SIP payload too big. Ignoring");
				return POM_OK;

			}
			// SIP message segmented in multiple fragz
			struct target_bin_msg_buff_msn *sip_msg = NULL;
			sip_msg = malloc(sizeof(struct target_bin_msg_buff_msn));
			memset(sip_msg, 0, sizeof(struct target_bin_msg_buff_msn));

			sip_msg->buffer = malloc(total_size + 1);
			memcpy(sip_msg->buffer, cp->buffer[cp->curdir] + m->cur_pos, msg_size);
			memset(sip_msg->buffer + msg_size, 0, (total_size + 1) - msg_size);


			sip_msg->total_size = total_size;
			sip_msg->cur_pos = msg_size;

			cp->sip_msg_buff[cp->curdir] = sip_msg;

			return POM_OK;
		}

		return target_process_sip_msn(t, cp, f, buddy_dest, buddy_guid, 0);
	}

	// Process the payload
	

	// We got a session id, this must be some payload
	int found = 0;
	struct target_file_transfer_msn *file = sess->file;
	while (file) {
		if (file->session_id == sess_id) {
			// doublecheck the user
			if (buddy_dest) {
				if (buddy_dest == file->buddy) {
					found = 1;
					break;
				}
			} else {
				if (cp->conv && cp->conv->parts) {
					if (!cp->conv->parts->next) {
						if (cp->conv->parts->buddy == file->buddy) {
							buddy_dest = cp->conv->parts->buddy;
							found = 1;
							break;
						}
					} else {
						pom_log(POM_LOG_DEBUG "More than one party in this conversation, cannot match file");
					}
				} else {
					pom_log(POM_LOG_TSHOOT "No participant in this connection, matching on the session ID only");
					found = 1;
					break;
				}
			}
		}
		file = file->next;
	}
	if (!found) {
		pom_log(POM_LOG_DEBUG "P2P File transfer with session SessionID %u was not found !", sess_id);
		return POM_OK;
	} 
	
	// Have the session last longer
	timer_dequeue(file->timer);
	timer_queue(file->timer, MSN_SESSION_TIMEOUT);

	// Check if we know what file type we are dealing with
	// If not, try to guess
	if (flags && file->type == msn_file_type_unknown) {
		if (flags & 0x10 && file->type != msn_file_type_transfer) {
			pom_log(POM_LOG_DEBUG "Flags 0x%X and file type unknown for session %u. It's probably a file transfer", flags, file->session_id);
			file->type = msn_file_type_transfer;
		} else if (flags & 0x20 && !(flags & 0x10) && file->type != msn_file_type_display_image) {
			pom_log(POM_LOG_DEBUG "Flags 0x%X and file type unknown for session %u. It's probably a file transfer", flags, file->session_id);
			file->type = msn_file_type_display_image;
		}
	}



	if (file->fd == -1) {

		if (!cp->session->user->account) // Account unknown, ignore
			return POM_OK;

		if (!msg_size) // Empty message, discard it
			return POM_OK;

		char fname[NAME_MAX + 1];
		if (file->type == msn_file_type_display_image) {
			if (!PTYPE_BOOL_GETVAL(priv->dump_avatar)) 
				return POM_OK;
			if (m->from) {
				// File is coming from someone
				strncpy(fname, m->from->account, NAME_MAX);
			} else {
				// File is sent by us
				strncpy(fname, cp->session->user->account, NAME_MAX);
			}
			strncat(fname, "-display-picture.png", NAME_MAX - strlen(fname));
		} else if (file->type == msn_file_type_transfer) {
			if (!PTYPE_BOOL_GETVAL(priv->dump_file_transfer)) 
				return POM_OK;
			struct tm tmp;
			localtime_r((time_t*)&f->tv.tv_sec, &tmp);
			if (file->filename) {
				char *format = "%Y%m%d-%H%M%S-";
				strftime(fname, NAME_MAX, format, &tmp);
				strncat(fname, file->filename, NAME_MAX - strlen(fname));
			} else {
				strncpy(fname, "file-transfered-", NAME_MAX);
				char *format = "%Y%m%d-%H%M%S.unk";
				strftime(fname + strlen(fname), NAME_MAX - strlen(fname), format, &tmp);

			}
		} else if (file->type == msn_file_type_unknown) {
			pom_log(POM_LOG_DEBUG "File type for session %u is unknown", file->session_id);
			return POM_OK;
		} else {
			pom_log(POM_LOG_DEBUG "Unsupported file type, dropping");
			return POM_OK;
		}

		// Make sure the account and filename doesn't contain '/'
		char *tmp_account = strdup(cp->session->user->account), *pos = NULL;
		while ((pos = strchr(tmp_account, '/')))
			*pos = '_';
		while ((pos = strchr(fname, '/')))
			*pos = '_';

		char filename[NAME_MAX + 1];
		strcpy(filename, cp->session->parsed_path);
		strncat(filename, tmp_account, NAME_MAX - strlen(filename));
		free(tmp_account);
		if (file->type == msn_file_type_display_image)
			strncat(filename, "/", NAME_MAX - strlen(filename));
		else
			strncat(filename, "/files/", NAME_MAX - strlen(filename));
		
		strncat(filename, fname, NAME_MAX - strlen(filename));
		int fd = target_file_open(NULL, filename, O_WRONLY | O_CREAT, 0666);
		
		if (fd == -1) {
			char errbuff[256];
			strerror_r(errno, errbuff, sizeof(errbuff) - 1);
			pom_log(POM_LOG_ERR "Error while opening file %s for writing", filename, errbuff);
			return POM_ERR;
		}

		perf_item_val_inc(priv->perf_cur_files, 1);

		if (cp->flags & MSN_CONN_FLAG_WLM2009_BIN) // WLM2009 doesn't provide the total_size
			total_size = msg_size + remaining_size;

		file->fd = fd;
		if (!file->len)
			file->len = total_size;
	
		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
		evt.buff = file->filename;
		evt.from = file->buddy;
		evt.type = msn_evt_file_transfer_start;
		evt.conv = cp->conv;
		evt.sess = cp->session;

		if (target_msn_session_event(&evt) == POM_ERR)
			return POM_ERR;

	}

	size_t offset = file->len - remaining_size - msg_size;

	if (offset < 0) {
		pom_log(POM_LOG_DEBUG "Invalid remaining size or msg_size. Ignoring");
		return POM_OK;
	}

	if (file->pos != offset) {
		pom_log(POM_LOG_TSHOOT "Chunks out of order ! current pos : %llu, given pos : %llu", (uint64_t)file->pos, (uint64_t)offset);
		if (lseek(file->fd, offset, SEEK_SET) == -1) {
			pom_log(POM_LOG_DEBUG "Could not seek to %z !", offset);
			return POM_OK;
		}
		file->pos = offset;
	}
	
	size_t res = 0, len = msg_size;
	while ((res = write(file->fd, cp->buffer[cp->curdir] + m->cur_pos, len))) {
		if (res == -1) {
			char errbuff[256];
			strerror_r(errno, errbuff, sizeof(errbuff) - 1);
			pom_log(POM_LOG_ERR "Write error : %s", errbuff);
			return POM_ERR;
		}
		m->cur_pos += res;
		len -= res;
	}

	file->pos += msg_size;
	file->written_len += msg_size;

	pom_log(POM_LOG_TSHOOT "P2P Payload : SessionID %u, ID %u, msg_size %u, flags 0x%X", sess_id, id, (long)msg_size, flags);
	m->cur_pos = m->tot_len;

	return POM_OK;

}

int target_process_sip_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct target_buddy_msn *buddy_dest, char *buddy_guid, int oob) {

	struct target_priv_msn *priv = t->target_priv;

	struct target_msg_msn *m = cp->msg[cp->curdir];

	// Find out about the SIP command
	
	char *first_line = line_split(cp); // SIP command

	if (!first_line) // End of the message
		return POM_OK;
	if (!strncasecmp(first_line, "INVITE", strlen("INVITE"))) {
		pom_log(POM_LOG_TSHOOT "P2P Got INVITE");
		m->sip_cmd = msn_msnmsgrp2p_sip_type_invite;

	} else if (!strncasecmp(first_line, "MSNSLP/1.0 200", strlen("MSNSLP/1.0 200"))) { // 200 OK
		pom_log(POM_LOG_TSHOOT "P2P Reply : %s", first_line);
		m->sip_cmd = msn_msnmsgrp2p_sip_type_200_ok;

	} else if (!strncasecmp(first_line, "MSNSLP/1.0 603", strlen("MSNSLP/1.0 603"))) { // 603 Decline
		pom_log(POM_LOG_TSHOOT "P2P Got 603 Decline");
		m->sip_cmd = msn_msnmsgrp2p_sip_type_error;

	} else if (!strncasecmp(first_line, "MSNSLP/1.0 500", strlen("MSNSLP/1.0 500"))) { // 500 Internal error
		pom_log(POM_LOG_TSHOOT "P2P Got 500 Internal Error");
		m->sip_cmd = msn_msnmsgrp2p_sip_type_error;

	} else if (!strncasecmp(first_line, "MSNSLP/1.0 481", strlen("MSNSLP/1.0 481"))) { // 481 No Such Call
		pom_log(POM_LOG_TSHOOT "P2P Got 481 No Such Call");
		m->sip_cmd = msn_msnmsgrp2p_sip_type_error;

	} else if (!strncasecmp(first_line, "ACK", strlen("ACK"))) {
		pom_log(POM_LOG_TSHOOT "P2P ACK");
		m->sip_cmd = msn_msnmsgrp2p_sip_type_ack;

	} else if (!strncasecmp(first_line, "BYE", strlen("BYE"))) {
		pom_log(POM_LOG_TSHOOT "P2P, Client sent bye");
		m->sip_cmd = msn_msnmsgrp2p_sip_type_bye;
	
	} else {
		pom_log(POM_LOG_DEBUG "Unknown SIP command : %s", first_line);
		return POM_OK;
	}



	struct msn_header *sip_hdrs = header_split(cp);

	struct target_session_priv_msn *sess = cp->session;

	struct target_file_transfer_msn *file = NULL;

	unsigned int hdr_num = 0;


	char *msn_p2p_mime_types[] = {
		"null",
		"application/x-msnmsgr-sessionreqbody",
		"application/x-msnmsgr-transdestaddrupdate",
		"application/x-msnmsgr-transreqbody",
		"application/x-msnmsgr-transrespbody",
		"application/x-msnmsgr-transudpswitch",
		"application/x-msnmsgr-turnsetup",
		"application/x-msnmsgr-sessionclosebody",
		"application/x-msnmsgr-session-failure-respbody",
		NULL,
	};


	struct msn_header *hdrs = NULL;
	
	for (hdr_num = 0; sip_hdrs[hdr_num].name; hdr_num++) {
		if (!strcasecmp(sip_hdrs[hdr_num].name, "Content-Type")) {
			int i;
			for (i = 0; msn_p2p_mime_types[i]; i++) {
				if (!strcasecmp(sip_hdrs[hdr_num].value, msn_p2p_mime_types[i])) {
					if (!hdrs)
						hdrs = header_split(cp);
				}
			}
			break;

		}

		if (!buddy_dest) { // Try to find the buddy from the "To" and "From" headers
			// We don't reuse the msg->from since it doesn't contain the buddy_guid
			if (!strcasecmp(sip_hdrs[hdr_num].name, "To") 
				|| !strcasecmp(sip_hdrs[hdr_num].name, "From")) {
				// Format is "<msnmsgr:account;guid>"
				if (strncasecmp(sip_hdrs[hdr_num].value, "<msnmsgr:", strlen("<msnmsgr:")))
					continue;
				sip_hdrs[hdr_num].value += strlen("<msnmsgr:");
				if (*(sip_hdrs[hdr_num].value + strlen(sip_hdrs[hdr_num].value) - 1) != '>')
					continue;
				*(sip_hdrs[hdr_num].value + strlen(sip_hdrs[hdr_num].value) - 1) = 0;
				buddy_guid = strchr(sip_hdrs[hdr_num].value, ';');
				if (buddy_guid) {
					*buddy_guid = 0;
					buddy_guid++;
				}
				
				struct target_buddy_list_session_msn *bud_lst = target_msn_session_found_buddy(cp, sip_hdrs[hdr_num].value, NULL, NULL, &f->tv);
				if (bud_lst)
					buddy_dest = bud_lst->bud;
				if (buddy_dest == sess->user)
					buddy_dest = NULL;
				if (m->from && buddy_dest && m->from != buddy_dest)
					pom_log(POM_LOG_DEBUG "Warning, destination buddy missmatch");
				if (buddy_dest) { // The account we found wasn't the user
					if (!cp->conv) // No conversation yet, adding this participant to create one
						target_msn_session_found_party(t, cp, sip_hdrs[hdr_num].value, NULL, &f->tv);
					if (buddy_guid)
						cp->flags |= MSN_CONN_FLAG_WLM2009_BIN;
				} else { // This was probably the account
					buddy_guid = NULL;
				}


			}
		}
	}

	free(sip_hdrs);

	if (!hdrs) {
		pom_log(POM_LOG_DEBUG "Unknown or no Content-Type found in SIP message");
		return POM_OK;
	}


	// Look for the session id

	int sess_id = -1;
	for (hdr_num = 0; hdrs[hdr_num].name; hdr_num++) {
		if (!strcasecmp(hdrs[hdr_num].name, "SessionID")) {
			if (sscanf(hdrs[hdr_num].value, "%u", &sess_id) != 1) {
				pom_log(POM_LOG_DEBUG "P2P invalid session id : %s", hdrs[hdr_num].value);
				free(hdrs);
				return POM_OK;
			}
			break;
		}
	}

	if (sess_id == 0) {
		// Session ID = 0 seems to be probe but not exchange of data
		pom_log(POM_LOG_TSHOOT "Session ID in SIP message is 0. Ignoring");
		free(hdrs);
		return POM_OK;

	}


	struct target_file_transfer_msn *tmp_file = NULL;
	if (sess_id != -1) {
		for (tmp_file = sess->file; tmp_file; tmp_file = tmp_file->next) {
			if (tmp_file->session_id == sess_id && tmp_file->buddy == buddy_dest) {
				file = tmp_file;
				break;
			}
		}
		if (!file) {
			if (m->sip_cmd == msn_msnmsgrp2p_sip_type_invite || m->sip_cmd == msn_msnmsgrp2p_sip_type_200_ok) {

				if (!cp->conv) {
					pom_log(POM_LOG_DEBUG "No conversation for this session yet. Ignoring new file");
				} else {

					struct target_session_priv_msn *sess = cp->session;

					file = malloc(sizeof(struct target_file_transfer_msn));
					memset(file, 0, sizeof(struct target_file_transfer_msn));
					file->fd = -1;
					file->session_id = sess_id;
					file->buddy = buddy_dest;
					if (buddy_guid) {
						file->buddy_guid = malloc(strlen(buddy_guid) + 1);
						strcpy(file->buddy_guid, buddy_guid);
					}

					file->timer = timer_alloc(file, f->input, target_session_timeout_msn);
					timer_queue(file->timer, MSN_SESSION_TIMEOUT);

					file->next = sess->file;
					if (sess->file)
						sess->file->prev = file;

					sess->file = file;
					file->conv = cp->conv;


					pom_log(POM_LOG_TSHOOT "New file transfer session : %u", sess_id);
				}
			}
		}
	} else {
		// Try to guess *g*
		int found = 0;
		for (tmp_file = sess->file; tmp_file; tmp_file = tmp_file->next) {
			if (tmp_file->buddy == buddy_dest) {
				if (!tmp_file->buddy_guid && !buddy_guid) {
					found++;
					file = tmp_file;
					continue;
				}


				if ((tmp_file->buddy_guid || buddy_guid) && (
					(tmp_file->buddy_guid && !buddy_guid) || 
					(!tmp_file->buddy_guid && buddy_guid))) // they must have a buddy if detected/present
					continue;

				if ((tmp_file->buddy_guid && buddy_guid && !strcasecmp(tmp_file->buddy_guid, buddy_guid))) {
					found++;
					file = tmp_file;
					continue;
				}

			}
		}

		if (found > 1)
			file = NULL;
	}

	if (file) {
		// Make the session last longer
		timer_dequeue(file->timer);
		timer_queue(file->timer, MSN_SESSION_TIMEOUT);
	}

	if (m->sip_cmd == msn_msnmsgrp2p_sip_type_bye || m->sip_cmd == msn_msnmsgrp2p_sip_type_error) {
		if (file) 
			target_session_close_file_msn(priv, file);
		free(hdrs);
		return POM_OK;
	}

	hdr_num = 0;

	enum msn_file_type file_type = msn_file_type_unknown;
	char *internal_addrs = NULL, *internal_port = NULL;
	char *external_addrs = NULL, *external_port = NULL;
	char *internal_addrs_and_ports = NULL, *external_addrs_and_ports = NULL;
	char *ipv6_addrs_and_ports = NULL, *ipv6_addrs = NULL, *ipv6_port = NULL;
	char *server_addr = NULL;

	char *b64_context = NULL;

	for (hdr_num = 0; hdrs[hdr_num].name; hdr_num++) {

		if (!strcasecmp(hdrs[hdr_num].name, "Context")) {
			b64_context = hdrs[hdr_num].value;

		} else if (!strcasecmp(hdrs[hdr_num].name, "EUF-GUID")) {
			if (!strcasecmp(hdrs[hdr_num].value, "{A4268EEC-FEC5-49E5-95C3-F126696BDBF6}")) { // Avatar
				pom_log(POM_LOG_TSHOOT "Session %u will transfer an avatar", sess_id);
				file_type = msn_file_type_display_image;
			} else if (!strcasecmp(hdrs[hdr_num].value, "{5D3E02AB-6190-11D3-BBBB-00C04F795683}")) { // File transfer
				pom_log(POM_LOG_TSHOOT "Session %u will transfer a file", sess_id);
				file_type = msn_file_type_transfer;
			} else {
				pom_log(POM_LOG_DEBUG "Unknown file EUF-GUID : %s for session %u", hdrs[hdr_num].value, sess_id);
			}

		} else if (!strcasecmp(hdrs[hdr_num].name, "Nat-Trav-Msg-Type")) {
			if (!strcasecmp(hdrs[hdr_num].value, "WLX-Nat-Trav-Msg-UDP-Switch")) {
				pom_log(POM_LOG_TSHOOT "Session switched to UDP");
				cp->flags |= MSN_CONN_FLAG_UDP;
			}

		} else if (!strcasecmp(hdrs[hdr_num].name, "srddA-lanretxE4vPI")) { // IPv4External-Addrs
			target_mirror_string_msn(hdrs[hdr_num].value);
			external_addrs = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "External IPv4 Addrs : %s", hdrs[hdr_num].value);

		} else if (!strcasecmp(hdrs[hdr_num].name, "troP-lanretxE4vPI")) { // IPv4External-Port
			target_mirror_string_msn(hdrs[hdr_num].value);
			external_port = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "External IPv4 Port : %s", hdrs[hdr_num].value);

		} else if (!strcasecmp(hdrs[hdr_num].name, "srddA-lanretnI4vPI")) { // IPv4Internal-Addrs
			target_mirror_string_msn(hdrs[hdr_num].value);
			internal_addrs = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "Internal IPv4 Addrs : %s", hdrs[hdr_num].value);

		} else if (!strcasecmp(hdrs[hdr_num].name, "troP-lanretnI4vPI")) { // IPv4Internal-Port
			target_mirror_string_msn(hdrs[hdr_num].value);
			internal_port = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "Internal IPv4 Port : %s", hdrs[hdr_num].value);

		} else if (!strcasecmp(hdrs[hdr_num].name, "stroPdnAsrddAlanretnI4vPI")) { // IPv4InternalAddrsAndPorts
			target_mirror_string_msn(hdrs[hdr_num].value);
			internal_addrs_and_ports = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "Internal IPv4 Addrs and ports : %s", hdrs[hdr_num].value);

		} else if (!strcasecmp(hdrs[hdr_num].name, "stroPdnAsrddAlanretxE4vPI")) { // IPv4ExternalAddrsAndPorts
			target_mirror_string_msn(hdrs[hdr_num].value);
			external_addrs_and_ports = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "External IPv4 Addrs and ports : %s", hdrs[hdr_num].value);

		} else if (!strcasecmp(hdrs[hdr_num].name, "stroPdnAsrddA6vPI")) { // IPv6AddrsAndPorts
			target_mirror_string_msn(hdrs[hdr_num].value);
			ipv6_addrs_and_ports = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "IPv6 Addrs and ports : %s", hdrs[hdr_num].value);

		} else if (!strcasecmp(hdrs[hdr_num].name, "IPv6-Addrs")) { // IPv6-Addrs
			ipv6_addrs = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "IPv6 Addrs : %s", hdrs[hdr_num].value);

		} else if (!strcasecmp(hdrs[hdr_num].name, "IPv6-Port")) { // IPv6-Port
			ipv6_port = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "IPv6 Port : %s", hdrs[hdr_num].value);

		} else if (!strcasecmp(hdrs[hdr_num].name, "ServerAddress")) {
			server_addr = hdrs[hdr_num].value;
			pom_log(POM_LOG_TSHOOT "ServerAddress : %s", hdrs[hdr_num].value);
		}

	}
	free(hdrs);

	if (file) {
		if (file->type == msn_file_type_unknown)
			file->type = file_type;
		else if (file_type != msn_file_type_unknown && file->type != file_type)
			pom_log(POM_LOG_DEBUG "File type changed : %u -> %u", file->type, file_type);
	}

	unsigned int flags = MSN_CONN_FLAG_P2P | (cp->flags & (MSN_CONN_FLAG_WLM2009_BIN | MSN_CONN_FLAG_UDP));
	if (oob)
		flags |= MSN_CONN_FLAG_OOB;
	if (internal_addrs && internal_port) {
		char *str, *saveptr = NULL, *token;
		for (str = internal_addrs; ; str = NULL) {
			token = strtok_r(str, " ", &saveptr);
			if (!token)
				break;
			target_add_expectation_msn(t, cp, f, token, internal_port, flags);
		}
	}

	if (external_addrs && external_port) {
		char *str, *saveptr = NULL, *token;
		for (str = external_addrs; ; str = NULL) {
			token = strtok_r(str, " ", &saveptr);
			if (!token)
				break;
			target_add_expectation_msn(t, cp, f, token, external_port, flags);
		}
	}

	if (internal_addrs_and_ports) {
		char *str, *saveptr = NULL, *token;
		for (str = internal_addrs_and_ports; ; str = NULL) {
			token = strtok_r(str, " ", &saveptr);
			if (!token)
				break;
			char *port = strchr(token, ':');
			if (!port)
				continue;
			*port = 0;
			port++;
			target_add_expectation_msn(t, cp, f, token, port, flags);
		}
	}

	if (external_addrs_and_ports) {
		char *str, *saveptr = NULL, *token;
		for (str = external_addrs_and_ports; ; str = NULL) {
			token = strtok_r(str, " ", &saveptr);
			if (!token)
				break;
			char *port = strchr(token, ':');
			if (!port)
				continue;
			*port = 0;
			port++;
			target_add_expectation_msn(t, cp, f, token, port, flags);
		}
	}

	if (ipv6_addrs_and_ports) {
		char *str, *saveptr = NULL, *token;
		for (str = ipv6_addrs_and_ports; ; str = NULL) {
			token = strtok_r(str, " ", &saveptr);
			if (!token)
				break;
			char *port = strchr(token, '#');
			if (!port)
				continue;
			*port = 0;
			port++;
			target_add_expectation_msn(t, cp, f, token, port, flags);
		}
	}

	if (ipv6_addrs && ipv6_port) {
		char *str, *saveptr = NULL, *token;
		for (str = ipv6_addrs; ; str = NULL) {
			token = strtok_r(str, " ", &saveptr);
			if (!token)
				break;
			target_add_expectation_msn(t, cp, f, token, ipv6_port, flags);
		}
	}

	if (server_addr) {
		int tmpflags = MSN_CONN_FLAG_STUN | (cp->flags & MSN_CONN_FLAG_WLM2009_BIN);
		if (oob)
			tmpflags |= MSN_CONN_FLAG_OOB;
		target_add_expectation_msn(t, cp, f, server_addr, "443", tmpflags);
	}

	if (b64_context) {
		int len = (strlen(b64_context) / 4) * 3 + 1;
		char *context = malloc(len);
		memset(context, 0, len);
		int outlen = base64_decode(context, b64_context, len);
		if (outlen == POM_ERR) {
			pom_log(POM_LOG_DEBUG "P2P Err while decoding Context : %s", b64_context);
		} else {

			if (!file->filename && file->type == msn_file_type_transfer && outlen >= sizeof(struct msn_file_transfer_context)) {
				// Of course, this crap is little endian ...
				struct msn_file_transfer_context *ctx = (struct msn_file_transfer_context*)context;
				ctx->len = le32(ctx->len); // Do not trust this value
				file->len = le64(ctx->file_size);
				if (!ctx->len > outlen) {
					pom_log(POM_LOG_DEBUG "Length provided in context is too big : %u, max %u", ctx->len, outlen);
				} else if (outlen > sizeof(struct msn_file_transfer_context)) {
					// And this crap is UTF-16 ...
					iconv_t cd = iconv_open("UTF-8", "UTF-16");
					if (cd == (iconv_t)-1) {
						pom_log(POM_LOG_DEBUG "Unable to open an iconv_t for UTF-16 to UTF-8");
					} else {
						size_t inbytesleft = outlen - offsetof(struct msn_file_transfer_context, filename);
						size_t outbytesleft = inbytesleft;
						file->filename = malloc(outbytesleft  + 1);
						memset(file->filename, 0, outbytesleft  + 1);
						char *inbuf = context + offsetof(struct msn_file_transfer_context, filename);
						char *outbuf = file->filename;
						while (iconv(cd, &inbuf, &inbytesleft, &outbuf, &outbytesleft) != -1) {
							if (!*outbuf)
								break;
						}
						if (!strlen(file->filename)) {
							free(file->filename);
							file->filename = NULL;
						} else {
							pom_log(POM_LOG_TSHOOT "Found filename \"%s\" for session %u", file->filename, file->session_id);
						}

						iconv_close(cd);
					}
				}

			}

		}
		free(context);
	}

	return POM_OK;
}

int target_process_uun_ubn_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	struct target_msg_msn *msg = cp->msg[cp->curdir];

	char *payload = cp->buffer[cp->curdir] + msg->cur_pos;

	int res = POM_OK;

	if (msg->tot_len - msg->cur_pos < 5) {
		pom_log(POM_LOG_DEBUG "UUN/UBN payload too short to contain valid data");
		target_free_msg_msn(cp, cp->curdir);
		return POM_OK;
	}

	if (!strncasecmp(payload, "<SNM", strlen("<SNM"))) {
		pom_log(POM_LOG_TSHOOT "P2P, Ignoring Shared New Media payload");
	} else if (!strncasecmp(payload, "<sip", strlen("<sip"))) {
		pom_log(POM_LOG_TSHOOT "P2P, Ignoring base64 encoded SIP payload"); 
	} else {
		res = target_process_sip_msn(t, cp, f, NULL, NULL, 1);
	}

	// Out of band message should not associate a conversation
	cp->conv = NULL;

	target_free_msg_msn(cp, cp->curdir);

	return res;
}

int target_process_mail_invite_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	struct target_msg_msn *m = cp->msg[cp->curdir];
	int len = m->tot_len - m->cur_pos;

	struct target_event_msn evt;
	memset(&evt, 0, sizeof(struct target_event_msn));
	memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
	evt.buff = malloc(len + 1);
	memcpy(evt.buff, cp->buffer[cp->curdir] + cp->msg[cp->curdir]->cur_pos, len);
	*(evt.buff + len) = 0;
	evt.from = m->from;
	evt.to = m->to;
	evt.type = msn_evt_mail_invite;
	evt.conv = cp->conv;
	evt.sess = cp->session;

	int res = target_msn_session_event(&evt);

	free(evt.buff);

	target_free_msg_msn(cp, cp->curdir);

	return res;
}


// Parse status message in UUX
int target_process_status_msg_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	struct target_msg_msn *m = cp->msg[cp->curdir];


	if (!m->from) {
		pom_log(POM_LOG_DEBUG "Uknnown source for status message");
		target_free_msg_msn(cp, cp->curdir);
		return POM_OK;
	}


	int len = m->tot_len - m->cur_pos;

	xmlDocPtr doc = NULL;
	xmlNodePtr root, cur;

	doc = xmlReadMemory(cp->buffer[cp->curdir] + cp->msg[cp->curdir]->cur_pos, len, "noname.xml", NULL, 0);

	if (!doc) {
		pom_log(POM_LOG_DEBUG "Unable to parse the XML formated status message");
		target_free_msg_msn(cp, cp->curdir);
		return POM_OK;
	}

	root = xmlDocGetRootElement(doc);

	if (!root) {
		pom_log(POM_LOG_DEBUG "Unexpected empty status message");
		xmlFreeDoc(doc);
		target_free_msg_msn(cp, cp->curdir);
		return POM_OK;
	}

	// Possible format :
	// <Data>
	// 	<PSM>Personal Status Message</PSM>
	// 	<CurrentMedia>Playing song</CurrentMedia>
	// 	<MachineGuid>Guid</MachineGuid>
	// 	<DDP>?</DDP>
	// 	<SignatureSound>?</SignatureSound>
	// 	<Scene>url encoded msnobj</Scene>
	// 	<ColorScheme>signed int</ColorScheme>
	// </Data>
	//
	// <EndpointData>
	// 	<Capabilities>numerical value</Capabilities>
	// </EndpointData>
	//
	// <PrivateEndpointData>
	// 	<EpName>Name of the PC</EpName>
	// 	<Idle>true/false</Idle>
	// 	<ClientType>1(numerical value)</ClientType>
	// 	<State>Status(IDL,NLN,BSY,...)</State>
	// </PrivateEndpointData>

	int res = POM_OK;

	cur = root->xmlChildrenNode;

	struct target_buddy_msn *buddy = m->from;

	// Let's try to parse the useful info
	if (!xmlStrcmp(root->name, (const xmlChar*) "Data")) {
		// MSNP 11->18
		while (cur) {
			if (!xmlStrcmp(cur->name, (const xmlChar*) "PSM")) { // Handle personal message

				struct target_event_msn evt;
				memset(&evt, 0, sizeof(struct target_event_msn));
				memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
				evt.type = msn_evt_personal_msg_change;
				evt.from = buddy;
				evt.conv = cp->conv;
				evt.sess = cp->session;

				char *psm = (char*) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
				if (psm) { // Let's see if it changed since last time
					if (!buddy->psm || strcmp(buddy->psm, psm)) {
						pom_log(POM_LOG_TSHOOT "Status message changed : %s", psm);
						free(buddy->psm);
						buddy->psm = malloc(strlen(psm) + 1);
						strcpy(buddy->psm, psm);

						evt.buff = buddy->psm;
						res = target_msn_session_broadcast_event(&evt);

					}
					xmlFree(psm);
				} else if (buddy->psm) {
					free(buddy->psm); // Message was unset
					buddy->psm = NULL;
					res = target_msn_session_broadcast_event(&evt);
				}

			} else if (!xmlStrcmp(cur->name, (const xmlChar*) "CurrentMedia")) {
				char *current_media = (char*) xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
				if (current_media) {
					pom_log(POM_LOG_TSHOOT "Currently playing song : %s", current_media);
					xmlFree(current_media);
				}
			}
			
			cur = cur->next;
		}
	} else if (!xmlStrcmp(root->name, (const xmlChar*) "EndpointData")) {
		// MSNP 17->18

		// do nothing, we don't care about it as there is no useful info
	} else if (!xmlStrcmp(root->name, (const xmlChar*) "PrivateEndpointData")) {
		// MSNP 17->18

		// do nothing, we don't care about it as there is no useful info
	} else {
		pom_log(POM_LOG_DEBUG "Unknown UUX payload");
	}


	xmlFreeDoc(doc);

	target_free_msg_msn(cp, cp->curdir);

	return res;
}

// Parse status message in ADL
int target_process_adl_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	struct target_msg_msn *m = cp->msg[cp->curdir];
	int len = m->tot_len - m->cur_pos;

	xmlDocPtr doc = NULL;
	xmlNodePtr root;

	doc = xmlReadMemory(cp->buffer[cp->curdir] + cp->msg[cp->curdir]->cur_pos, len, "noname.xml", NULL, 0);

	if (!doc) {
		pom_log(POM_LOG_DEBUG "Unable to parse the XML formated status message");
		target_free_msg_msn(cp, cp->curdir);
		return POM_OK;
	}

	root = xmlDocGetRootElement(doc);

	if (!root) {
		pom_log(POM_LOG_DEBUG "Unexpected empty status message");
		xmlFreeDoc(doc);
		target_free_msg_msn(cp, cp->curdir);
		return POM_OK;
	}

	// Format :
	// <ml>
	// 	<d n="domain1">
	// 		<c n="account" l="list_id" t="type" />
	// 		...
	// 	</d>
	// 	....
	// 	<t><c n="tel number"/></t>
	// </ml>


	if (xmlStrcmp(root->name, (const xmlChar*) "ml")) {
		pom_log(POM_LOG_DEBUG "Unexpected root tag : %s", root->name);
		xmlFreeDoc(doc);
		target_free_msg_msn(cp, cp->curdir);
		return POM_OK;
	}

	xmlNodePtr domainPtr = root->xmlChildrenNode;

	while (domainPtr) {
		if (!xmlStrcmp(domainPtr->name, (const xmlChar*) "d")) {
	
			char *domain = (char *) xmlGetProp(domainPtr, (const xmlChar*) "n");
			if (!domain) {
				pom_log(POM_LOG_DEBUG "No domain given in <d> tag");
				domainPtr = domainPtr->next;
				continue;
			}
		
			xmlNodePtr contactPtr = domainPtr->xmlChildrenNode;

			while (contactPtr) {
				if (!xmlStrcmp(contactPtr->name, (const xmlChar*) "c")) {

					char *account = (char *) xmlGetProp(contactPtr, (const xmlChar*) "n");
					if (!account) {
						pom_log(POM_LOG_DEBUG "No account given in <c> tag");
						contactPtr = contactPtr->next;
						continue;
					}

					char *list_id_str = (char *) xmlGetProp(contactPtr, (const xmlChar*) "l");
					if (!list_id_str) {
						pom_log(POM_LOG_DEBUG "No list id given in <c> tag");
						xmlFree(account);
						contactPtr = contactPtr->next;
						continue;
					}
					
					unsigned int list_id;
					if (sscanf(list_id_str, "%u", &list_id) != 1) {
						pom_log(POM_LOG_DEBUG "Unable to parse the list id : %s", list_id_str);
						xmlFree(account);
						xmlFree(list_id_str);
						contactPtr = contactPtr->next;
						continue;
					}

					char *full_account = malloc(strlen(account) + strlen("@") + strlen(domain) + 1);
					strcpy(full_account, account);
					strcat(full_account, "@");
					strcat(full_account, domain);

					xmlFree(account);
					xmlFree(list_id_str);

					struct target_buddy_list_session_msn *buddy = target_msn_session_found_buddy(cp, full_account, NULL, NULL, &f->tv);
					free(full_account);

					if (buddy && (list_id & 0x4)) // blocked ?
						buddy->blocked = 1;

				} else {
					pom_log(POM_LOG_DEBUG "Unexpected tag %s in <d> tag", contactPtr->name);
				}
				contactPtr = contactPtr->next;
			}

			xmlFree(domain);
		} else if(!xmlStrcmp(domainPtr->name, (const xmlChar*) "t")) {
			// Not handled yet
		} else {
			pom_log(POM_LOG_DEBUG "Unexpected tag %s in <ml> tag", domainPtr->name);
		}
		
		domainPtr = domainPtr->next;
	}


	xmlFreeDoc(doc);

	target_free_msg_msn(cp, cp->curdir);

	return POM_OK;
}
int target_process_mail_notification_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs) {

	struct msn_header *hdrs2 = header_split(cp);
	unsigned int hdr_num = 0;

	char *from = NULL, *from_addr = NULL, *subject = NULL;

	while (hdrs2[hdr_num].name) {
		if (!from && !strcasecmp(hdrs2[hdr_num].name, "From"))
			from = hdrs2[hdr_num].value;
		else if (!from_addr && !strcasecmp(hdrs2[hdr_num].name, "From-Addr"))
			from_addr = hdrs2[hdr_num].value;
		else if (!subject && !strcasecmp(hdrs2[hdr_num].name, "Subject"))
			subject = hdrs2[hdr_num].value;

		if (from && from_addr && subject)
			break;

		hdr_num++;
	}

	if (from && from_addr && subject) {
		pom_log(POM_LOG_TSHOOT "New email received from \"%s\" <%s> : \"%s\"", from, from_addr, subject);
		// TODO : decode quoted-printable encoded subject
	}

	target_free_msg_msn(cp, cp->curdir);
	free(hdrs2);
	return POM_OK;

}

int target_process_msg_profile_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f, struct msn_header *hdrs) {

	unsigned int hdr_num = 0;
	while (hdrs[hdr_num].name) {
		if (!strcasecmp(hdrs[hdr_num].name, "Nickname"))
			if (target_msn_session_found_friendly_name(t, cp, hdrs[hdr_num].value, &f->tv) == POM_ERR)
				return POM_ERR;


		hdr_num++;
	}

	return POM_OK;
}

int target_mirror_string_msn(char *value) {

	size_t len = strlen(value);
	char *tmp = malloc(len + 1);
	strcpy(tmp, value);

	int i;
	for (i = len; i > 0; i--)
		value[i - 1] = tmp[len - i];

	free(tmp);
	return POM_OK;

}


int target_session_timeout_msn(void *priv) {
	struct target_file_transfer_msn *file = priv;
	pom_log(POM_LOG_TSHOOT "Session %u timed out. Closing.", file->session_id);

	return target_session_close_file_msn(file->conv->sess->target_priv, file);
}

int target_session_close_file_msn(struct target_priv_msn *priv, struct target_file_transfer_msn *file) {

	int res = POM_OK;

	pom_log(POM_LOG_TSHOOT "P2P file of SessionID %u closed", file->session_id);
	
	if (file->fd != -1) {
		close(file->fd);
		if (file->written_len < file->len) {
			pom_log(POM_LOG_DEBUG "File for session %u is not complete");
			perf_item_val_inc(priv->perf_partial_files, 1);
		}

		perf_item_val_inc(priv->perf_tot_files, 1);
		perf_item_val_inc(priv->perf_cur_files, -1);

		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));

		// Use the time directly from the input
		get_current_time(&evt.tv);
		evt.buff = file->filename;
		evt.from = file->buddy;
		evt.type = msn_evt_file_transfer_end;
		evt.conv = file->conv;
		evt.sess = file->conv->sess;


		res = target_msn_session_event(&evt);
	}

	if (file->prev)
		file->prev->next = file->next;
	else
		file->conv->sess->file = file->next;

	if (file->next)
		file->next->prev = file->prev;
	
	if (file->buddy_guid)
		free(file->buddy_guid);
	
	if (file->filename)
		free(file->filename);

	timer_cleanup(file->timer);

	free(file);
	
	return res;
}
