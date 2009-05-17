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
#include "target_msn_session.h"

#include <fcntl.h>


struct target_connection_party_msn *target_msn_session_found_party(struct target_conntrack_priv_msn *cp, char *account, char *nick) {

	if (!strchr(account, '@')) {
		pom_log(POM_LOG_DEBUG "Invalid account : %s", account);
		return POM_OK;
	}

	char *sc = strchr(account, ';');
	if (sc) // Remove ;{guid} from account name
		*sc = 0;


	if (cp->session->user.account && !strcmp(account, cp->session->user.account)) {
		// No kidding, we are talking in our own conversation ?
		return POM_OK;
	}


	// First see if we this buddy already joined the conversation
	struct target_connection_party_msn *tmp = cp->parts;
	while (tmp) {
		if (!strcmp(tmp->buddy->account, account)) 
			break;
		tmp = tmp->next;
	}

	if (!tmp) { // If not, see if we already know this guy
		struct target_buddy_msn *bud = cp->session->buddies;
		while (bud) {
			if (!strcmp(bud->account, account))
				break;
			bud = bud->next;
		}

		if (!bud) { // we don't even know this guy. Add him to the buddy list
			pom_log(POM_LOG_TSHOOT "Got buddy \"%s\" (%s)", nick, account);

			bud = malloc(sizeof(struct target_buddy_msn));
			memset(bud, 0, sizeof(struct target_buddy_msn));
			bud->account = malloc(strlen(account) + 1);
			strcpy(bud->account, account);
			if (nick) {
				bud->nick = malloc(strlen(nick) + 1);
				strcpy(bud->nick, nick);
			}

			bud->next = cp->session->buddies;
			cp->session->buddies = bud;
		}

		pom_log(POM_LOG_TSHOOT "Added user %s to the conversation", account);
		tmp = malloc(sizeof(struct target_connection_party_msn));
		memset(tmp, 0, sizeof(struct target_connection_party_msn));
		tmp->buddy = bud;

		if (cp->parts) {
			pom_log(POM_LOG_DEBUG "More than one party joined !");
		}

		tmp->next = cp->parts;
		cp->parts = tmp;
	}

	
	if (nick && !tmp->buddy->nick) {
		tmp->buddy->nick = malloc(strlen(nick) + 1);
		strcpy(tmp->buddy->nick, nick);
	}

	return tmp;
}


struct target_buddy_msn *target_msn_session_found_buddy(struct target_conntrack_priv_msn *cp, char *account, char *nick, char *group_list) {


	char *sc = strchr(account, ';');
	if (sc) // Remove extra ;{guid}
		*sc = 0;

	// Make sure the buddy isn't the account
	if (cp->session->user.account && !strcmp(cp->session->user.account, account))
		return &cp->session->user;

	struct target_buddy_msn *bud = cp->session->buddies;
	while (bud) {
		if (!strcmp(account, bud->account))
			break;
		bud = bud->next;
	}

	// Mr Buddy wasn't found

	if (!bud) {
		bud = malloc(sizeof(struct target_buddy_msn));
		memset(bud, 0, sizeof(struct target_buddy_msn));

		bud->account = malloc(strlen(account) + 1);
		strcpy(bud->account, account);

		bud->next = cp->session->buddies;
		cp->session->buddies = bud;
		
		pom_log(POM_LOG_TSHOOT "Got buddy (%s)", account);

	}

	if (nick && !bud->nick) {
		bud->nick = malloc(strlen(nick) + 1);
		strcpy(bud->nick, nick);
	}

	if (group_list && !bud->group_list) {
		bud->group_list = malloc(strlen(group_list) + 1);
		strcpy(bud->group_list, group_list);
	}


	return bud;

}

int target_msn_session_found_group(struct target_conntrack_priv_msn *cp, char *name, char *id) {

	struct target_buddy_group_msn *grp = cp->session->groups;

	while (grp) {
		if (!strcmp(grp->id, id)) {
			pom_log(POM_LOG_TSHOOT "Group already found in the group list");
			return POM_OK;
		}
		grp = grp->next;
	}

	// Group wasn't found
	
	pom_log(POM_LOG_TSHOOT "Got group \"%s\" (%s)", name, id);
	grp = malloc(sizeof(struct target_buddy_group_msn));
	memset(grp, 0, sizeof(struct target_buddy_group_msn));
	grp->name = malloc(strlen(name) + 1);
	strcpy(grp->name, name);
	grp->id = malloc(strlen(id) + 1);
	strcpy(grp->id, id);

	grp->next = cp->session->groups;
	cp->session->groups = grp;

	return POM_OK;

}

int target_msn_session_found_friendly_name(struct target_conntrack_priv_msn *cp, char *friendly_name, struct timeval *time) {


	struct target_session_priv_msn *sess = cp->session;

	if (!sess->user.nick || strcmp(sess->user.nick, friendly_name)) {
		if (sess->user.nick)
			free(sess->user.nick);

		sess->user.nick = malloc(strlen(friendly_name) + 1);
		strcpy(sess->user.nick, friendly_name);

		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, time, sizeof(struct timeval));
		evt.buff = friendly_name;
		evt.type = msn_evt_friendly_name_change;

		target_msn_session_event(cp, &evt);

	}

	return POM_OK;

}


int target_msn_session_found_account(struct target *t, struct target_conntrack_priv_msn *cp, char *account) {

	struct target_priv_msn *priv = t->target_priv;


	// remove extra ;{guid} from account name
	char *sc = strchr(account, ';');
	if (sc)
		*sc = 0;

	if (!cp->session->user.account) {
		// See if we added ourself as a buddy by mistake
		struct target_buddy_msn *prevbud = NULL, *bud = cp->session->buddies;
	
		while (bud) {
			if (!strcmp(account, bud->account)) { // It seems so
				struct target_buddy_msn *user = &cp->session->user;
				user->account = bud->account;

				if (user->nick)
					free(user->nick);
				user->nick = bud->nick;

				if (user->psm)
					free(user->psm);
				user->psm = bud->psm;

				user->status = bud->status;

				if (!prevbud)
					cp->session->buddies = bud->next;
				else
					prevbud->next = bud->next;

				struct target_event_msn *tmp_evt = cp->conv_buff;
				while (tmp_evt) {
					if (tmp_evt->from == bud)
						tmp_evt->from = user;
					if (tmp_evt->to == bud)
						tmp_evt->to = user;
					tmp_evt = tmp_evt->next;
				}

				if (bud->group_list)
					free(bud->group_list);
				free(bud);
				break;

			}
			prevbud = bud;
			bud = bud->next;
		}

		// Try to find another session with the same account
		
		struct target_session_priv_msn *tmpsess = priv->sessions;
		while (tmpsess) {
			if (tmpsess != cp->session && tmpsess->user.account && !strcmp(tmpsess->user.account, account))
				break;
			tmpsess = tmpsess->next;
		}
		
		if (tmpsess) {
			pom_log(POM_LOG_TSHOOT "Existing session found for account %s, merging", account);
			target_msn_session_merge(priv, cp, tmpsess);

		} else {
			if (!cp->session->user.account) {
				cp->session->user.account = malloc(strlen(account) + 1);
				strcpy(cp->session->user.account, account);
			}
			pom_log(POM_LOG_TSHOOT "User account is %s", cp->session->user.account);

		}
	} else {

		if (strcmp(cp->session->user.account, account)) {
			pom_log(POM_LOG_DEBUG "Warning, account missmatch for the msn connection");
			return POM_ERR;
		}
	}

	while (cp->conv_buff) {
		struct target_event_msn *tmp = cp->conv_buff;
		cp->conv_buff = cp->conv_buff->next;
		if (tmp->from) {
			pom_log(POM_LOG_TSHOOT "Buffered event from %s to %s", tmp->from, account);
		} else {
			pom_log(POM_LOG_TSHOOT "Buffered event from %s to conversation", account);
		}

		target_msn_session_process_event(cp, tmp);

		if (tmp->buff)
			free(tmp->buff);
		free(tmp);

	}

	return POM_OK;
}


struct target_session_priv_msn *target_msn_session_merge(struct target_priv_msn *priv, struct target_conntrack_priv_msn *cp, struct target_session_priv_msn *old_sess) {

	struct target_session_priv_msn *new_sess = cp->session;

	// Let's update all the connections which uses this session
	struct target_conntrack_priv_msn *ct_privs = priv->ct_privs;
	while (ct_privs) {
		if (ct_privs->session == new_sess) {
			new_sess->refcount--;
			ct_privs->session = old_sess;
			old_sess->refcount++;
		}
		ct_privs = ct_privs->next;
	}

	if (new_sess->refcount != 0) 
		pom_log(POM_LOG_WARN "Warning, session refcount is not 0 !");

	// First, merge groups
	struct target_buddy_group_msn *new_grp = new_sess->groups;
	while (new_grp) {
		struct target_buddy_group_msn *old_grp = old_sess->groups;
		while (old_grp) {
			if (!strcmp(new_grp->id, old_grp->id)) // Group match
				break;
			old_grp = old_grp->next;
		}

		new_sess->groups = new_grp->next;

		if (!old_grp) { // Corresponding group wasn't found, assign to existing session
			new_grp->next = old_sess->groups;
			old_sess->groups = new_grp;
		} else {
			if (new_grp->name) {
				if (!old_grp->name)
					old_grp->name = new_grp->name;
				else
					free(new_grp->name);
			}
			
			free(new_grp->id);
			free(new_grp);

		}

		new_grp = new_sess->groups;
	}
	
	struct target_buddy_msn *new_bud = new_sess->buddies;
	while (new_bud) {
		struct target_buddy_msn *old_bud = old_sess->buddies;
		while (old_bud) {
			if (!strcmp(new_bud->account, old_bud->account))
				break;
			old_bud = old_bud->next;
		}
		
		new_sess->buddies = new_bud->next;

		if (!old_bud) { // Buddy wasn't found. Assign to existion session
			new_bud->next = old_sess->buddies;
			old_sess->buddies = new_bud;
		} else {
			// Buddy found, let's discard it
			
			// Update events buddy

			struct target_event_msn *tmp_evt = cp->conv_buff;
			while (tmp_evt) {
				if (tmp_evt->from == new_bud)
					tmp_evt->from = old_bud;
				if (tmp_evt->to == new_bud)
					tmp_evt->to = old_bud;
				tmp_evt = tmp_evt->next;
			}

			if (new_bud->nick) {
				if (!old_bud->nick)
					old_bud->nick = new_bud->nick;
				else
					free(new_bud->nick);
			}

			if (new_bud->group_list) {
				if (!old_bud->group_list)
					old_bud->group_list = new_bud->group_list;
				else
					free(new_bud->group_list);
			}

			if (new_bud->psm) {
				if (!old_bud->psm)
					old_bud->psm = new_bud->psm;
				else
					free(new_bud->psm);
			}

			free(new_bud->account);	
			free(new_bud);
		}
		new_bud = new_sess->buddies;
	}

	// Merge the remaining stuff
	
	if (new_sess->user.nick) {
		if (!old_sess->user.nick || strcmp(old_sess->user.nick, new_sess->user.nick)) {
			if (old_sess->user.nick)
				free(old_sess->user.nick);
			old_sess->user.nick = new_sess->user.nick;
		}
	}

	if (new_sess->user.status != msn_status_unknown)
		old_sess->user.status = new_sess->user.status;

	free(new_sess->user.account);

	// Remove the session from the sessions list
	if (new_sess->prev)
		new_sess->prev->next = new_sess->next;
	else	
		priv->sessions = new_sess->next;
		
	if (new_sess->next)
		new_sess->next->prev = new_sess->prev;

	free(new_sess);

	return old_sess;
}

int target_msn_session_event(struct target_conntrack_priv_msn *cp, struct target_event_msn *evt) {

	char *account = cp->session->user.account;

	if (!account) { // We don't know the account, buffer this event

		pom_log(POM_LOG_TSHOOT "Session account not known yet. Buffering conversation event");
		struct target_event_msn *new_evt = NULL;
		new_evt = malloc(sizeof(struct target_event_msn));
		memset(new_evt, 0, sizeof(struct target_event_msn));

		new_evt->from = evt->from;
		new_evt->to = evt->to;

		if (evt->buff) {
			new_evt->buff = malloc(strlen(evt->buff) + 1);
			strcpy(new_evt->buff, evt->buff);
		}

		memcpy(&new_evt->tv, &evt->tv, sizeof(struct timeval));
		new_evt->type = evt->type;
	
		// Add it at the end
		if (!cp->conv_buff) {
			cp->conv_buff = new_evt;
		} else {
			struct target_event_msn *tmp = cp->conv_buff;
			while (tmp->next)
				tmp = tmp->next;
			tmp->next = new_evt;
		}

		return POM_OK;
	}


	return target_msn_session_process_event(cp, evt);

}

int target_msn_session_process_event(struct target_conntrack_priv_msn *cp, struct target_event_msn *evt) {

	struct tm tmp_time;
	localtime_r((time_t*)&evt->tv.tv_sec, &tmp_time);

	if (!(evt->type & MSN_EVT_SESSION_MASK) && (cp->fd == -1)) {

		char outstr[17];
		memset(outstr, 0, sizeof(outstr));
		// /YYYYMMDD-HH.txt
		char *format = "-%Y%m%d-%H.txt";
		strftime(outstr, sizeof(outstr), format, &tmp_time);

		char filename[NAME_MAX + 1];
		strcpy(filename, cp->parsed_path);
		strncat(filename, cp->session->user.account, NAME_MAX - strlen(filename));
		strncat(filename, "/", NAME_MAX - strlen(filename));
		char *party_account = NULL;
		if (!cp->parts)
			party_account = evt->from->account;
		else
			party_account = cp->parts->buddy->account;
		if (!party_account) {
			pom_log(POM_LOG_DEBUG "Not enough info to open the file !");
			return POM_OK;
		}
		strncat(filename, party_account, NAME_MAX - strlen(filename));
		strncat(filename, outstr, NAME_MAX - strlen(filename));

		// Open could do the job but it's better to use the API if it changes later on
		cp->fd = target_file_open(NULL, filename, O_WRONLY | O_CREAT | O_APPEND, 0666);
		if (cp->fd == POM_ERR)
			return POM_ERR;
	}

	// Open the session logs
	
	struct target_session_priv_msn *sess = cp->session;

	if ((evt->type & MSN_EVT_SESSION_MASK) && (sess->fd == -1)) {

		char outstr[24];
		memset(outstr, 0, sizeof(outstr));
		// session-YYYYMMDD-HH.txt
		char *format = "session-%Y%m%d-%H.txt";
		strftime(outstr, sizeof(outstr), format, &tmp_time);

		char filename[NAME_MAX + 1];
		strcpy(filename, cp->parsed_path);
		strncat(filename, sess->user.account, NAME_MAX - strlen(filename));
		strncat(filename, "/", NAME_MAX - strlen(filename));
		strncat(filename, outstr, NAME_MAX - strlen(filename));

		// Open could do the job but it's better to use the API if it changes later on
		sess->fd = target_file_open(NULL, filename, O_WRONLY | O_CREAT | O_APPEND, 0666);
		if (sess->fd == POM_ERR)
			return POM_ERR;
	}

	char timestamp[12];
	memset(timestamp, 0, sizeof(timestamp));
	char *format = "[%H:%M:%S] ";
	strftime(timestamp, sizeof(timestamp), format, &tmp_time);

	int res = 0;

	switch (evt->type) {
		case msn_evt_buddy_join:
			res += target_msn_session_write(cp->fd, timestamp);
			res += target_msn_session_write(cp->fd, "User ");
			res += target_msn_session_write(cp->fd, evt->from->account);
			res += target_msn_session_write(cp->fd, " joined the conversation\n");
			break;
		case msn_evt_message:
			res += target_msn_session_write(cp->fd, timestamp);
			if (evt->from) {
				res += target_msn_session_write(cp->fd, evt->from->account);
			} else {
				res += target_msn_session_write(cp->fd, sess->user.account);
			}
			res += target_msn_session_write(cp->fd, ": ");
			res += target_msn_session_write(cp->fd, evt->buff);
			res += target_msn_session_write(cp->fd, "\n");

			break;
		case msn_evt_buddy_leave:
			res += target_msn_session_write(cp->fd, timestamp);
			if (evt->from == &sess->user) {
				res += target_msn_session_write(cp->fd, "Conversation closed by user\n");
			} else {
				res += target_msn_session_write(cp->fd, "User ");
				res += target_msn_session_write(cp->fd, evt->from->account);
				res += target_msn_session_write(cp->fd, " left the conversation\n");
			}
			break;
		case msn_evt_friendly_name_change: {
			int len = strlen(evt->buff) + 1;
			char *decoded_friendly_name = malloc(len);
			memset(decoded_friendly_name, 0, len);
			len = url_decode(decoded_friendly_name, evt->buff, len);
			if (len == POM_ERR) {
				pom_log(POM_LOG_WARN "Unable to decode the friendly name \"%s\"", evt->buff);
				free(decoded_friendly_name);
				break;
			}
			res += target_msn_session_write(sess->fd, timestamp);
			res += target_msn_session_write(sess->fd, "Friendly name set to \"");
			res += target_msn_session_write(sess->fd, decoded_friendly_name);
			res += target_msn_session_write(sess->fd, "\"\n");
			free(decoded_friendly_name);
			break;
		}
		case msn_evt_status_change:
			res += target_msn_session_write(sess->fd, timestamp);
			if (evt->from == &sess->user) {
				res += target_msn_session_write(sess->fd, "Status changed to : ");
				res += target_msn_session_write(sess->fd, evt->buff);
				res += target_msn_session_write(sess->fd, "\n");
			} else {
				res += target_msn_session_write(sess->fd, "User ");
				res += target_msn_session_write(sess->fd, evt->from->account);
				res += target_msn_session_write(sess->fd, " is now ");
				res += target_msn_session_write(sess->fd, evt->buff);
				res += target_msn_session_write(sess->fd, "\n");
			}
			break;
		case msn_evt_user_disconnect:
			res += target_msn_session_write(sess->fd, timestamp);
			res += target_msn_session_write(sess->fd, "User disconnected : ");
			res += target_msn_session_write(sess->fd, evt->buff);
			res += target_msn_session_write(sess->fd, "\n");
			break;
		case msn_evt_mail_invite:
			res += target_msn_session_write(sess->fd, timestamp);
			res += target_msn_session_write(sess->fd, "User invited ");
			res += target_msn_session_write(sess->fd, evt->to->account);
			res += target_msn_session_write(sess->fd, " via email");
			if (evt->buff) {
				res += target_msn_session_write(sess->fd, " : \"");
				res += target_msn_session_write(sess->fd, evt->buff);
				res += target_msn_session_write(sess->fd, "\"");
			}
			res += target_msn_session_write(sess->fd, "\n");
			break;
		case msn_evt_personal_msg_change:
			res += target_msn_session_write(sess->fd, timestamp);
			if (evt->from == &sess->user) {
				if (evt->buff) {
					res += target_msn_session_write(sess->fd, "Personal Message set to : \"");
					res += target_msn_session_write(sess->fd, evt->buff);
					res += target_msn_session_write(sess->fd, "\"\n");
				} else {
					res += target_msn_session_write(sess->fd, "Personal Message unset\n");	
				}
			} else {
				res += target_msn_session_write(sess->fd, "User ");
				res += target_msn_session_write(sess->fd, evt->from->account);
				if (evt->buff) {
					res += target_msn_session_write(sess->fd, " set his personal message to : \"");
					res += target_msn_session_write(sess->fd, evt->buff);
					res += target_msn_session_write(sess->fd, "\"\n");
				} else {
					res += target_msn_session_write(sess->fd, " removed his personal message\n");
				}
			}
			break;
	}

	if (res != POM_OK)
		return POM_ERR;

	return POM_OK;

}

int target_msn_session_write(int fd, char *buff) {

	size_t len = strlen(buff);
	size_t res = 0, pos = 0;
	while ((res = write(fd, buff + pos, len - pos)) && pos < len) {
		if (res == -1)
			return POM_ERR;
		pos += res;
	}

	return POM_OK;
}


int target_msn_session_dump_buddy_list(struct target_conntrack_priv_msn *cp) {


	struct target_session_priv_msn *sess = cp->session;

	struct target_buddy_msn *bud = sess->buddies;

	if (!bud)
		return POM_OK;

	int res = POM_OK;
	res += target_msn_session_write(sess->fd, "--- BUDDY LIST DUMP START ---\n");

	while (bud) {
		res += target_msn_session_write(sess->fd, "BUDDY : ");
		res += target_msn_session_write(sess->fd, bud->account);
		if (bud->nick) {
			res += target_msn_session_write(sess->fd, " \"");
			unsigned int len = strlen(bud->nick) + 1;
			char *decoded_nick = malloc(len);
			memset(decoded_nick, 0, len);
			len = url_decode(decoded_nick, bud->nick, len);
			res += target_msn_session_write(sess->fd, decoded_nick);
			free(decoded_nick);
			res += target_msn_session_write(sess->fd, "\"");
		}
		res += target_msn_session_write(sess->fd, "\n");

		bud = bud->next;
	}

	res += target_msn_session_write(sess->fd, "--- BUDDY LIST DUMP END ---\n");

	if (res != POM_OK)
		return POM_ERR;
	
	return POM_OK;
}
