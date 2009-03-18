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

#include "target_msn.h"
#include "target_msn_msgs.h"
#include "target_msn_session.h"

#include <fcntl.h>

struct msn_mime_type {

	char *name;
	int (*handler) (struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
};


static struct msn_mime_type msn_mime_types[] = {
	{ "dummu/unknown", NULL },
	{ "application/x-msnmsgr-sessionreqbody", NULL },
	{ "application/x-msnmsgr-transdestaddrupdate", NULL },
	{ "application/x-msnmsgr-transreqbody", NULL },
	{ "application/x-msnmsgr-transrespbody", NULL },
	{ "application/x-msnmsgrp2p", target_process_mime_msnmsgrp2p_msg },
	{ "text/plain", target_process_mime_text_plain_msg },
	{ "text/x-mms-emoticon", NULL },
	{ "text/x-msmsgscontrol", target_process_mime_msmsgscontrol_msg },
	{ "text/x-msnmsgr-datacast", NULL },
	{ 0, 0},
};

char* line_split (struct target_conntrack_priv_msn *cp) {

	char *line = cp->buffer[cp->curdir] + cp->msg[cp->curdir]->cur_pos;

	char *eol = strstr(line, "\r\n");
	if (!eol) 
		return NULL;
	*eol = 0;

	int len = eol - line + 2;
	cp->msg[cp->curdir]->cur_pos += len;

	return line;
}

int target_process_msg_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	struct target_msg_msn *msg = cp->msg[cp->curdir];

	while (msg->cur_pos < msg->tot_len) {

		char *line = line_split(cp);
		if (!line) {
			target_free_msg_msn(cp, cp->curdir);
			return POM_OK;
		}

		char *arg = strchr(line, ':');
		if (arg) {
			do { arg++; } while (*arg == ' ');

			if (!strncasecmp(line, "MIME-Version:", strlen("MIME-Version:"))) {
				pom_log(POM_LOG_TSHOOT "Header MIME-Version : %s", arg);
				continue;
			} else if (!strncasecmp(line, "Content-Type:", strlen("Content-Type:"))) {
				int id = 0;
				char *coma = strchr(arg, ';');
				if (coma)
					*coma = 0; // Strip the rest of the mime-type
				for (id = 0; msn_mime_types[id].name; id++) {
					if (!strcasecmp(msn_mime_types[id].name, arg)) {
						msg->mime_type = id;
						pom_log(POM_LOG_TSHOOT "Header Content-Type found : %s", arg);
						int res = POM_OK;
						if (msn_mime_types[id].handler)
							res = (*msn_mime_types[id].handler) (t, cp, f);
						else
							pom_log(POM_LOG_DEBUG "Unhandled mime-type : %s", arg);
						// Done with the message
						target_free_msg_msn(cp, cp->curdir);
						return res;
					}
				}
				if (!msg->mime_type)
					pom_log(POM_LOG_DEBUG "Header Content-Type unknown : %s", arg);
			} else if (!strncasecmp(line, "P2P-Dest:", strlen("P2P-Dest:"))) {
				char *dest = strchr(line, ':');
				do { dest++; } while (*dest == ' ');
				pom_log(POM_LOG_TSHOOT "P2PDest : %s", dest);
			}
		}

	}


	// Done with the message
	target_free_msg_msn(cp, cp->curdir);
	return POM_OK;

}


int target_process_mime_msmsgscontrol_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {

	char *line = line_split(cp);
	if (!line)
		return POM_OK;

	if (!strncasecmp(line, "TypingUser:", strlen("TypingUser:"))) {
		char *user = strchr(line, ':');
		if (!user)
			return POM_OK;
		do { user++; } while (*user == ' ');

		pom_log(POM_LOG_TSHOOT "User %s is typing", user);
	}

	return POM_OK;
}


int target_process_mime_text_plain_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {


	int dir = cp->curdir;

	struct target_msg_msn *m = cp->msg[dir];

	enum msn_text_plain_subtypes {
		msn_text_plain_subtype_header = 0,
		msn_text_plain_subtype_payload,
	};

	while (m->cur_pos < m->tot_len) {
		char *line = line_split(cp);
		switch (m->subtype) {
			case msn_text_plain_subtype_header:
				if (!line)
					return POM_OK;
				if (!strncasecmp(line, "X-MMS-IM-Format:", strlen("X-MMS-IM-Format:"))) {
					char *format = strchr(line, ':');
					if (!format)
						return POM_OK;
					do { format++; } while (*format == ' ');

				} else if (!strlen(line)) {
					m->subtype = msn_text_plain_subtype_payload;
				}
				break;
			case msn_text_plain_subtype_payload: {
				struct target_conv_event_msn evt;
				memcpy(&evt.tv, &f->tv, sizeof(struct timeval));
				evt.from = m->from;
				evt.buff = cp->buffer[dir] + m->cur_pos;
				evt.type = target_conv_event_type_message;

				int res = target_msn_session_conv_event(cp, &evt);
				m->cur_pos = m->tot_len;
				return res;
			}
			default:
				break;
		}
	}
	
	return POM_OK;
}

int target_process_mime_msnmsgrp2p_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f) {


	struct target_msg_msn *m = cp->msg[cp->curdir];
	enum msn_text_plain_subtypes {
		msn_msnmsgrp2p_subtype_header = 0,
		msn_msnmsgrp2p_subtype_header2,
		msn_msnmsgrp2p_subtype_invite,
		msn_msnmsgrp2p_subtype_200_ok,
		msn_msnmsgrp2p_subtype_ack,
		msn_msnmsgrp2p_subtype_bye,
		msn_msnmsgrp2p_subtype_payload,
	};

	char header[48];
	uint32_t sess_id = 0, id = 0, msg_size = 0, flags = 0;
	uint64_t offset = 0, total_size = 0;


	while (m->cur_pos < m->tot_len) {


		char *line = NULL;
		if (m->subtype != msn_msnmsgrp2p_subtype_payload) { // Are we handling a payload
			// No so split the line
			line = line_split(cp);
			if (!line) {
				return POM_OK;
			}
		} else {
			int found = 0;
			struct target_file_transfer_msn *file = cp->file, *fprev = NULL;
			while (file) {
				if (file->session_id == sess_id) {
					found = 1;
					break;
				}
				fprev = file;
				file = file->next;
			}
			if (!found) {
				pom_log(POM_LOG_DEBUG "P2P File transfer with session SessionID %u was not found !", sess_id);
				return POM_OK;
			}

			if (offset == 0) {
				if (file->type == target_file_type_unknown) {
					// Ok, no idea what this is, let's see if it could be a display image
					if (msg_size > 3 && !memcmp(cp->buffer[cp->curdir] + m->cur_pos, PNG_SIGNATURE, strlen(PNG_SIGNATURE))) {
						// Looks like it is
						file->type = target_file_type_display_image;
					} else {
						file->type = target_file_type_unsupported;
					}
				}
				char fname[NAME_MAX + 1];
				if (file->type == target_file_type_display_image) {
					if (m->from) {
						// File is coming from someone
						strncpy(fname, m->from, NAME_MAX);
					} else {
						// File is sent by us
						strncpy(fname, cp->session->account, NAME_MAX);
					}
					strncat(fname, "-display-picture.png", NAME_MAX - strlen(fname));
				} else {
					pom_log(POM_LOG_TSHOOT "Unsupported file type, dropping");
					return POM_OK;
				}

				if (!msg_size) // Empty message, discard it
					return POM_OK;

				if (!cp->session->account) // Account unknown, ignore
					return POM_OK;

				char filename[NAME_MAX + 1];
				strcpy(filename, cp->parsed_path);
				strncat(filename, cp->session->account, NAME_MAX - strlen(filename));
				strncat(filename, "/", NAME_MAX - strlen(filename));
				strncat(filename, fname, NAME_MAX - strlen(filename));
				int fd = target_file_open(NULL, filename, O_WRONLY | O_CREAT, 0666);
				
				if (fd == -1) {
					pom_log(POM_LOG_WARN "Error while opening file %s", filename);
					return POM_ERR;
				}

				file->fd = fd;
				file->len = total_size;

			}

			if (file->fd == -1)
				return POM_OK;
			
			write(file->fd, cp->buffer[cp->curdir] + m->cur_pos, msg_size);
			pom_log(POM_LOG_TSHOOT "P2P Payload : SessionID %u, ID %u, offset %lu, msg_size %u, total_size %lu, flags 0x%X", sess_id, id, (long)offset, (long)msg_size, (long)total_size, flags);
			if (offset + msg_size == total_size) {
				pom_log(POM_LOG_TSHOOT "P2P Transfer completed for SessionID : %u", sess_id);
				if (fprev)
					fprev->next = file->next;
				else
					cp->file = file->next;
				close(file->fd);
				free(file);
			}
			m->cur_pos = m->tot_len;
			return POM_OK;
		}

		switch (m->subtype) {
			case msn_msnmsgrp2p_subtype_header: // First header that contains P2PDest
				if (!strlen(line)) {
					// End of first header. 48 byte binary header follows
					// Stupid protocol that mix plain text and binary !
					memcpy(header, cp->buffer[cp->curdir] + m->cur_pos, sizeof(header));
					m->cur_pos += 48;
					// FIXME why little endian ?
					memcpy(&sess_id, header, sizeof(sess_id));
					memcpy(&id, header + 4, sizeof(id));
					memcpy(&offset, header + 8, sizeof(offset));
					memcpy(&total_size, header + 16, sizeof(total_size));
					memcpy(&msg_size, header + 24, sizeof(msg_size));
					memcpy(&flags, header + 28, sizeof(flags));

					if (sess_id) {
						if (total_size == 4) { // Discard useless data preparation message
							return POM_OK; // Ignore this crap
						}

						// We got a session id, this must be some payload
						m->subtype = msn_msnmsgrp2p_subtype_payload;
					} else {
						// Session id == 0, probably negociation
						m->subtype = msn_msnmsgrp2p_subtype_header2;
					}
				} else if (!memcmp(line, "P2P-Dest:", strlen("P2P-Dest:"))) {
					char *arg = strchr(line, ':');
					*arg = 0;
					do { arg++; } while (*arg == ' ');
					pom_log(POM_LOG_TSHOOT "P2P Dest : %s", arg);
				}
				break;
			case msn_msnmsgrp2p_subtype_header2: { // Handle what is after the 48 bytes
				if (!memcmp(line, "INVITE", strlen("INVITE"))) { // INVITE, new file transfer
					pom_log(POM_LOG_TSHOOT "P2P INVITE : New file");
					struct target_file_transfer_msn *file = NULL;
					file = malloc(sizeof(struct target_file_transfer_msn));
					memset(file, 0, sizeof(struct target_file_transfer_msn));
					file->fd = -1;
				
					file->next = cp->file;
					cp->file = file;
					m->subtype = msn_msnmsgrp2p_subtype_invite;
					break;

				} else if (!memcmp(line, "MSNSLP/1.0", strlen("MSNSLP/1.0"))) { // Got an OK reply (hopefully :)
					pom_log(POM_LOG_TSHOOT "P2P Reply : %s", line);
					m->subtype = msn_msnmsgrp2p_subtype_200_ok;
					break;
				} else if (!memcmp(line, "ACK", strlen("ACK"))) {
					pom_log(POM_LOG_TSHOOT, "P2P ACK");
					m->subtype = msn_msnmsgrp2p_subtype_ack;
				} else if (!memcmp(line, "BYE", strlen("BYE"))) {
					pom_log(POM_LOG_TSHOOT "P2P, Client sent bye");
					m->subtype = msn_msnmsgrp2p_subtype_bye;
				} else {
					pom_log(POM_LOG_DEBUG "Unhandled P2P message : %s", line);
				}
				break;
			}
			case msn_msnmsgrp2p_subtype_invite: { // Handle the INVITE response
				char *arg = strchr(line, ':');
				if (!arg)
					break;
				*arg = 0;
				do { arg++; } while (*arg == ' ');
				
				// The newly added file is at the front of the list
				if (!strcasecmp(line, "SessionID")) {
					if (sscanf(arg, "%u", &cp->file->session_id) != 1) {
						pom_log(POM_LOG_DEBUG "P2P invalid session id : %s", arg);
						return POM_OK;
					}
					pom_log(POM_LOG_TSHOOT "P2P SessionID : %u", cp->file->session_id);
				} else if (!strcasecmp(line, "Context")) {
					int len = (strlen(arg) * 3 / 4) + 1;
					char *context = malloc(len);
					memset(context, 0, len);
					int outlen = base64_decode(context, arg);
					if (outlen == POM_ERR) {
						pom_log(POM_LOG_DEBUG "P2P Err while decoding Context : %s", arg);
					} else {
						pom_log(POM_LOG_TSHOOT "P2P Decoded context (%u, %u) : %s", len, outlen, context);
					}
					free(context);
				} else if (m->from && !strcasecmp(line, "To")) {
					// We got incoming message from server
					char *account = strchr(arg, ':');
					if (!account) 
						break;
					account++;
					if (account[strlen(account) - 1] != '>')
						break;
					account[strlen(account) - 1] = 0;
					target_msn_session_found_account(cp, account);
				} else if (!m->from && !strcasecmp(line, "From")) {
					char *account = strchr(arg, ':');
					if (!account) 
						break;
					account++;
					if (account[strlen(account) - 1] != '>')
						break;
					account[strlen(account) - 1] = 0;
					// We got a message to the server
					target_msn_session_found_account(cp, account);
				} else if (!strcasecmp(line, "EUF-GUID")) {
					if (!strcasecmp(arg, "{A4268EEC-FEC5-49E5-95C3-F126696BDBF6}")) {
						cp->file->type = target_file_type_display_image;
					} else {
						pom_log(POM_LOG_DEBUG "Unknown file EUF-GUID : %s", arg);
						return POM_OK;
					}
				}
				break;
			}
			case msn_msnmsgrp2p_subtype_200_ok: { // Handle the OK response
				char *arg = strchr(line, ':');
				if (!arg)
					break;
				*arg = 0;
				do { arg++; } while (*arg == ' ');

				if (!strcasecmp(line, "SessionID")) {
					int sess_id = 0;
					if (sscanf(arg, "%u", &sess_id) != 1) {
						pom_log(POM_LOG_DEBUG "P2P invalid session id : %s", arg);
						return POM_OK;
					}
					struct target_file_transfer_msn *file = cp->file;
					while (file) {
						if (file->session_id == sess_id) {
							pom_log(POM_LOG_TSHOOT "P2P Transfer starting for SessionID : %u", sess_id);
							break;
						}
						file = file->next;
					}
					if (!file) {
						pom_log(POM_LOG_TSHOOT "P2P OK without invite : P2P Transfer starting for SessionID : %u", sess_id);
						struct target_file_transfer_msn *file = NULL;
						file = malloc(sizeof(struct target_file_transfer_msn));
						memset(file, 0, sizeof(struct target_file_transfer_msn));
						file->fd = -1;
						file->session_id = sess_id;
					
						file->next = cp->file;
						cp->file = file;
					}
					
				}
				break;
			}
			case msn_msnmsgrp2p_subtype_bye: { // Handle the BYE response
				char *arg = strchr(line, ':');
				if (!arg)
					break;
				*arg = 0;
				do { arg++; } while (*arg == ' ');

				if (!strcasecmp(line, "SessionID")) {
					int sess_id = 0;
					if (sscanf(arg, "%u", &sess_id) != 1) {
						pom_log(POM_LOG_DEBUG "P2P invalid session id : %s", arg);
						return POM_OK;
					}
					int found = 0;
					struct target_file_transfer_msn *file = cp->file, *fprev = NULL;
					while (file) {
						if (file->session_id == sess_id) {
							pom_log(POM_LOG_TSHOOT "P2P Transfer ended for SessionID : %u", sess_id);
							if (fprev)
								fprev->next = file->next;
							else
								cp->file = file->next;
							free(file);
							found = 1;
							break;
						}
						fprev = file;
						file = file->next;
					}
					if (!found)
						pom_log(POM_LOG_DEBUG "P2P File transfer with session SessionID %u was not found !", sess_id);
					
				}
				break;

			}
			default:
				break;
		}
	
	}

	return POM_OK;
}
