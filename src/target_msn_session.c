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


struct target_connection_party_msn *target_msn_session_add_party(struct target_conntrack_priv_msn *cp, char *account, char *nick) {

	if (!strchr(account, '@')) {
		pom_log(POM_LOG_DEBUG "Invalid account : %s", account);
		return POM_OK;
	}

	char *sc = strchr(account, ';');
	if (sc) // Remove ;{guid} from account name
		*sc = 0;

	struct target_connection_party_msn *tmp = cp->parts;
	while (tmp) {
		if (!strcmp(tmp->account, account)) 
			break;
		tmp = tmp->next;
	}

	if (!tmp) {
		pom_log(POM_LOG_TSHOOT "Added user %s to the conversation", account);
		tmp = malloc(sizeof(struct target_connection_party_msn));
		memset(tmp, 0, sizeof(struct target_connection_party_msn));
		tmp->account = malloc(strlen(account) + 1);
		strcpy(tmp->account, account);

		if (cp->parts) {
			pom_log(POM_LOG_DEBUG "More than one party joined !");
		}

		tmp->next = cp->parts;
		cp->parts = tmp;
	}

	
	if (nick && !tmp->nick) {
		tmp->nick = malloc(strlen(nick) + 1);
		strcpy(tmp->nick, nick);
	}

	return tmp;
}


int target_msn_session_found_buddy(struct target_conntrack_priv_msn *cp, char *account, char *nick, char *group_list) {


	struct target_buddy_msn *bud = cp->session->buddies;
	while (bud) {
		if (!strcmp(account, bud->account)) {
			pom_log(POM_LOG_TSHOOT "Buddy already in the list of buddies");
			return POM_OK;
		}
		bud = bud->next;
	}

	// Mr Buddy wasn't found
	
	bud = malloc(sizeof(struct target_buddy_msn));
	memset(bud, 0, sizeof(struct target_buddy_msn));
	bud->account = malloc(strlen(account) + 1);
	strcpy(bud->account, account);
	char *sc = strchr(bud->account, ';');
	if (sc) // Remove extra ;
		*sc = 0;


	if (nick) {
		bud->nick = malloc(strlen(nick) + 1);
		strcpy(bud->nick, nick);
	}
	

	if (group_list) {
		bud->group_list = malloc(strlen(group_list) + 1);
		strcpy(bud->group_list, group_list);
	}

	pom_log(POM_LOG_TSHOOT "Got buddy \"%s\" (%s)", nick, account);

	bud->next = cp->session->buddies;
	cp->session->buddies = bud;

	return POM_OK;

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

	if (!sess->friendly_name || strcmp(sess->friendly_name, friendly_name)) {
		if (sess->friendly_name)
			free(sess->friendly_name);

		sess->friendly_name = malloc(strlen(friendly_name) + 1);
		strcpy(sess->friendly_name, friendly_name);

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

	struct target_session_priv_msn *sess = cp->session;

	char *sc = strchr(account, ';');
	if (sc)
		*sc = 0;

	if (!sess->account) {
		// First, try to find another session with the same account
		
		struct target_session_priv_msn *tmpsess = priv->sessions;
		while (tmpsess) {
			if (tmpsess->account && !strcmp(tmpsess->account, account))
				break;
			tmpsess = tmpsess->next;
		}
		
		if (tmpsess) {
			pom_log(POM_LOG_TSHOOT "Existing session found for account %s, merging", account);
			sess = target_msn_session_merge(priv, tmpsess, sess);

		} else {
			sess->account = malloc(strlen(account) + 1);
			strcpy(sess->account, account);
			pom_log(POM_LOG_TSHOOT "User account is %s", sess->account);

		}
	} else {

		if (strcmp(sess->account, account)) {
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

		free(tmp->from);
		free(tmp->buff);
		free(tmp);

	}

	return POM_OK;
}


struct target_session_priv_msn *target_msn_session_merge(struct target_priv_msn *priv, struct target_session_priv_msn *old_sess, struct target_session_priv_msn *new_sess) {

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
				
			free(new_bud);
		}
		new_bud = new_sess->buddies;
	}

	// Merge the remaining stuff
	
	if (new_sess->friendly_name) {
		if (!old_sess->friendly_name || strcmp(old_sess->friendly_name, new_sess->friendly_name)) {
			if (old_sess->friendly_name)
				free(old_sess->friendly_name);
			old_sess->friendly_name = new_sess->friendly_name;
		}
	}

	if (new_sess->status != msn_status_unknown)
		old_sess->status = new_sess->status;

	free(new_sess->account);

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

	char *account = cp->session->account;

	if (!account) { // We don't know the account, buffer this event

		pom_log(POM_LOG_TSHOOT "Session account not known yet. Buffering conversation event");
		struct target_event_msn *new_evt = NULL;
		new_evt = malloc(sizeof(struct target_event_msn));
		memset(new_evt, 0, sizeof(struct target_event_msn));

		if (evt->from) {
			new_evt->from = malloc(strlen(evt->from) + 1);
			strcpy(new_evt->from, evt->from);
		}

		if (evt->to) {
			new_evt->to = malloc(strlen(evt->to) + 1);
			strcpy(new_evt->to, evt->to);
		}

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
		strncat(filename, cp->session->account, NAME_MAX - strlen(filename));
		strncat(filename, "/", NAME_MAX - strlen(filename));
		char *party_account = NULL;
		if (!cp->parts)
			party_account = evt->from;
		else
			party_account = cp->parts->account;
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
		strncat(filename, sess->account, NAME_MAX - strlen(filename));
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
		case msn_evt_user_join:
			res += target_msn_session_write(cp->fd, timestamp);
			res += target_msn_session_write(cp->fd, "User ");
			res += target_msn_session_write(cp->fd, evt->from);
			res += target_msn_session_write(cp->fd, " joined the conversation\n");
			break;
		case msn_evt_message:
			res += target_msn_session_write(cp->fd, timestamp);
			if (evt->from) {
				res += target_msn_session_write(cp->fd, evt->from);
			} else {
				res += target_msn_session_write(cp->fd, sess->account);
			}
			res += target_msn_session_write(cp->fd, ": ");
			res += target_msn_session_write(cp->fd, evt->buff);
			res += target_msn_session_write(cp->fd, "\n");

			break;
		case msn_evt_user_leave:
			res += target_msn_session_write(cp->fd, timestamp);
			res += target_msn_session_write(cp->fd, "User ");
			res += target_msn_session_write(cp->fd, evt->from);
			res += target_msn_session_write(cp->fd, " left the conversation\n");
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
			res += target_msn_session_write(sess->fd, "Status changed to : ");
			res += target_msn_session_write(sess->fd, evt->buff);
			res += target_msn_session_write(sess->fd, "\n");
			break;
		case msn_evt_user_disconnect:
			res += target_msn_session_write(sess->fd, timestamp);
			res += target_msn_session_write(sess->fd, "User disconnected : ");
			res += target_msn_session_write(sess->fd, evt->buff);
			res += target_msn_session_write(sess->fd, "\n");
			break;
		case msn_evt_mail_invite:
			res += target_msn_session_write(sess->fd, timestamp);
			res += target_msn_session_write(sess->fd, "User");
			if (evt->from) {
				res += target_msn_session_write(sess->fd, " (");
				res += target_msn_session_write(sess->fd, evt->from);
				res += target_msn_session_write(sess->fd, ")");
			}
			res += target_msn_session_write(sess->fd, " invited ");
			res += target_msn_session_write(sess->fd, evt->to);
			res += target_msn_session_write(sess->fd, " via email");
			if (evt->buff) {
				res += target_msn_session_write(sess->fd, " : \"");
				res += target_msn_session_write(sess->fd, evt->buff);
				res += target_msn_session_write(sess->fd, "\"");
			}
			res += target_msn_session_write(sess->fd, "\n");
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
