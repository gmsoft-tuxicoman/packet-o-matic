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

#include "ptype_bool.h"

#include <fcntl.h>


struct target_connection_party_msn *target_msn_session_found_party(struct target *t, struct target_conntrack_priv_msn *cp, char *account, char *nick, struct timeval *time) {

	if (!strchr(account, '@')) {
		pom_log(POM_LOG_DEBUG "Invalid account : %s", account);
		return NULL;
	}

	char *sc = strchr(account, ';');
	if (sc) // Remove ;{guid} from account name
		*sc = 0;


	if (cp->session->user.account && !strcmp(account, cp->session->user.account)) {
		// No kidding, we are talking in our own conversation ?
		return NULL;
	}


	// First see if we this buddy already joined the conversation
	struct target_connection_party_msn *tmp = NULL;
	if (cp->conv) {
		tmp = cp->conv->parts;
		while (tmp) {
			if (!strcmp(tmp->buddy->account, account)) 
				break;
			tmp = tmp->next;
		}
	}

	int send_join_evt = 0;

	if (!tmp) { // If not, see if we already know this guy
		struct target_buddy_msn *bud = cp->session->buddies;
		while (bud) {
			if (!strcmp(bud->account, account))
				break;
			bud = bud->next;
		}


		if (!bud) { // we don't even know this guy. Add him to the buddy list
			pom_log(POM_LOG_TSHOOT "Got buddy %s", nick, account);

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

		struct target_conversation_msn *conv = cp->conv;
		if (!conv) {
			// Buddy may be in a conversation already
			// Let's look for an existing conversation where he's alone
			for (conv = cp->session->conv; conv && (conv->parts->buddy != bud || conv->parts->next); conv = conv->next);

			if (conv) { // Found him
				cp->conv = conv;
				conv->refcount++;
				return conv->parts;
			}  else {
				conv = malloc(sizeof(struct target_conversation_msn));
				memset(conv, 0, sizeof(struct target_conversation_msn));
				conv->fd = -1;
				conv->sess = cp->session;

				conv->next = cp->session->conv;

				if (cp->session->conv)
					cp->session->conv->prev = conv;

				cp->session->conv = conv;

				cp->conv = conv;
				conv->refcount++;
			}

		}

		pom_log(POM_LOG_TSHOOT "Added user %s to the conversation", account);
		tmp = malloc(sizeof(struct target_connection_party_msn));
		memset(tmp, 0, sizeof(struct target_connection_party_msn));
		tmp->buddy = bud;
		tmp->joined = 1;

		tmp->next = conv->parts;
		conv->parts = tmp;

		send_join_evt = 1;


		if (conv->parts->next) { // Little debug
			pom_log(POM_LOG_DEBUG "More than one party joined !");
		}

	}

	if (!tmp->joined) {
		tmp->joined = 1;
		send_join_evt = 1;
	}

	if (send_join_evt) {
		// Send the join event
		struct target_event_msn evt;
		memset(&evt, 0, sizeof(struct target_event_msn));
		memcpy(&evt.tv, time, sizeof(struct timeval));
		evt.from = tmp->buddy;
		evt.type = msn_evt_buddy_join;
		evt.sess = cp->session;
		evt.conv = cp->conv;

		// We can't really do error checking here but it's gonna be caught elsewhere
		target_msn_session_event(&evt);
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

int target_msn_session_found_friendly_name(struct target *t, struct target_conntrack_priv_msn *cp, char *friendly_name, struct timeval *time) {

	int res = POM_OK;

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
		evt.sess = cp->session;
		evt.conv = cp->conv;

		res = target_msn_session_event(&evt);

	}

	return res;

}


int target_msn_session_found_account(struct target *t, struct target_conntrack_priv_msn *cp, char *account) {

	struct target_priv_msn *priv = t->target_priv;

	int res = POM_OK;

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

				// Update conversation events
				struct target_event_msn *tmp_evt = NULL; 
				if (cp->conv && cp->conv->evt_buff)
					tmp_evt = cp->conv->evt_buff;
				while (tmp_evt) {
					if (tmp_evt->from == bud)
						tmp_evt->from = user;
					if (tmp_evt->to == bud)
						tmp_evt->to = user;
					tmp_evt = tmp_evt->next;
				}

				// Update sesion events
				tmp_evt = cp->session->evt_buff;
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
			return POM_OK;
		}
	}

	if (cp->conv) {

		// Process conversation events
		struct target_conversation_msn *conv = cp->conv;
		while (conv->evt_buff) {
			struct target_event_msn *tmp = conv->evt_buff;
			conv->evt_buff = conv->evt_buff->next;

			char *from = "undefined", *to = "undefined";
			if (tmp->from)
				from = tmp->from->account;
			if (tmp->to)
				to = tmp->to->account;
			pom_log(POM_LOG_TSHOOT "Buffered event from %s to %s, session of : %s", from, to, account);

			res += target_msn_session_process_event(tmp);

			if (tmp->buff)
				free(tmp->buff);
			free(tmp);

		}

	}

	// Process session events
	while (cp->session->evt_buff) {

			struct target_event_msn *tmp = cp->session->evt_buff;
			cp->session->evt_buff = cp->session->evt_buff->next;

			char *from = "undefined", *to = "undefined";
			if (tmp->from)
				from = tmp->from->account;
			if (tmp->to)
				to = tmp->to->account;
			pom_log(POM_LOG_TSHOOT "Buffered event from %s to %s, session of : %s", from, to, account);

			res += target_msn_session_process_event(tmp);

			if (tmp->buff)
				free(tmp->buff);
			free(tmp);

	}

	if (res != POM_OK)
		return POM_ERR;

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

	// Merge buddies
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
			
			// Update conversation participants
			struct target_conversation_msn *new_conv = new_sess->conv;
			while (new_conv) {
				struct target_connection_party_msn *new_party = new_conv->parts;
				while (new_party) {
					if (new_party->buddy == new_bud)
						new_party->buddy = old_bud;
					new_party = new_party->next;
				}

				new_conv = new_conv->next;
			}
			
			// Update conversation events
			if (cp->conv) {
				struct target_event_msn *tmp_evt = cp->conv->evt_buff;
				while (tmp_evt) {
					if (tmp_evt->from == new_bud)
						tmp_evt->from = old_bud;
					if (tmp_evt->to == new_bud)
						tmp_evt->to = old_bud;
					tmp_evt = tmp_evt->next;
				}
			}

			// Update session events
			struct target_event_msn *tmp_evt = new_sess->evt_buff;
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

	// Merge conversations
	struct target_conversation_msn *new_conv = new_sess->conv;
	while (new_conv) {
		struct target_conversation_msn *tmp_conv = new_conv->next;
		struct target_conversation_msn *old_conv = old_sess->conv;
	
		while (old_conv) {
			struct target_connection_party_msn *new_party = new_conv->parts;
			unsigned int found = 0, count = 0;
			while (new_party) {
				count++;
				struct target_connection_party_msn *old_party = old_conv->parts;
				while (old_party) {
					if (new_party->buddy == old_party->buddy) {
						found++;
						break;
					}
					old_party = old_party->next;
				}
				new_party = new_party->next;
			}
			if (found == count) 
				break;

			old_conv = old_conv->next;
		}


		if (old_conv) {
			// Conversations are the same, we can discard the new one
			while (new_conv->parts) { // Free up participants
				struct target_connection_party_msn *new_party = new_conv->parts;
				new_conv->parts = new_party->next;
				free(new_party);
			}
			
			// Attach conversation events to existing conversation
			struct target_event_msn *tmp_evt = new_conv->evt_buff;
			while (tmp_evt) {
				tmp_evt->sess = old_sess;
				tmp_evt->conv = old_conv;
				tmp_evt = tmp_evt->next;
			}
			tmp_evt = old_conv->evt_buff;
			while (tmp_evt && tmp_evt->next)
				tmp_evt = tmp_evt->next;
			if (!tmp_evt)
				old_conv->evt_buff = new_conv->evt_buff;
			else
				tmp_evt->next = new_conv->evt_buff;

			// Replace conversation in the files
			struct target_file_transfer_msn *file = new_sess->file;
			while (file) {
				if (file->conv == new_conv)
					file->conv = old_conv;
				file = file->next;
			}

			// Replace the conversation in the contrack_privs
			ct_privs = priv->ct_privs;
			while (ct_privs) {
				if (ct_privs->conv == new_conv) {
					new_conv->refcount--;
					ct_privs->conv = old_conv;
					old_conv->refcount++;
				}
				ct_privs = ct_privs->next;
			}
			free(new_conv);
		} else {
			// Conversations are not the same, attach it to the old session
			old_sess->conv->prev = new_conv;
			new_conv->next = old_sess->conv;
			new_conv->prev = NULL;
			old_sess->conv = new_conv;

			// Update conversation events
			struct target_event_msn *tmp_evt = new_conv->evt_buff;
			while (tmp_evt) {
				tmp_evt->sess = old_sess;
			}
		}


		new_conv = tmp_conv;		
	}

	// Merge session events
	struct target_event_msn *tmp_evt = old_sess->evt_buff;
	while (tmp_evt && tmp_evt->next)
		tmp_evt = tmp_evt->next;
	if (!tmp_evt)
		old_sess->evt_buff = new_sess->evt_buff;
	else
		tmp_evt->next = new_sess->evt_buff;

	// Merge files
	struct target_file_transfer_msn *file = old_sess->file;
	if (!file) {
		old_sess->file = new_sess->file;
	} else {
		while (file->next)
			file = file->next;
		file->next = new_sess->file;
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
	
	free(new_sess->parsed_path);
	free(new_sess);

	return old_sess;
}

int target_msn_session_event(struct target_event_msn *evt) {


	if (!evt->sess) {
		pom_log(POM_LOG_DEBUG "Missing session for event");
		return POM_OK;
	}

	char *account = evt->sess->user.account;

	if (!account) { // We don't know the account, buffer this event

		pom_log(POM_LOG_TSHOOT "Session account not known yet. Buffering conversation event");
		struct target_event_msn *new_evt = NULL;
		new_evt = malloc(sizeof(struct target_event_msn));
		memset(new_evt, 0, sizeof(struct target_event_msn));

		new_evt->sess = evt->sess;
		new_evt->conv = evt->conv;
		new_evt->from = evt->from;
		new_evt->to = evt->to;

		if (evt->buff) {
			new_evt->buff = malloc(strlen(evt->buff) + 1);
			strcpy(new_evt->buff, evt->buff);
		}

		memcpy(&new_evt->tv, &evt->tv, sizeof(struct timeval));
		new_evt->type = evt->type;


		if (evt->type & MSN_EVT_SESSION_MASK) {
			evt->conv = NULL; // discard conv as it won't be used
			if (!evt->sess->evt_buff) {
				evt->sess->evt_buff = new_evt;
			} else {
				struct target_event_msn *tmp = evt->sess->evt_buff;
				while (tmp->next)
					tmp = tmp->next;
				tmp->next = new_evt;
			}

		} else {
			if (!evt->conv) {
				pom_log(POM_LOG_WARN "No conversation found");
				return POM_OK;
			}

			// Add it at the end
			if (!evt->conv->evt_buff) {
				evt->conv->evt_buff = new_evt;
			} else {
				struct target_event_msn *tmp = evt->conv->evt_buff;
				while (tmp->next)
					tmp = tmp->next;
				tmp->next = new_evt;
			}
		}

		return POM_OK;
	}


	return target_msn_session_process_event(evt);

}

int target_msn_session_process_event(struct target_event_msn *evt) {

	struct target_priv_msn *priv = evt->sess->target_priv;


	struct target_conversation_msn *conv = evt->conv;
	struct target_session_priv_msn *sess = evt->sess;

	if (!(evt->type & MSN_EVT_SESSION_MASK) && !conv) {
		struct target_buddy_msn *buddy = NULL;
		if (evt->from && evt->from != &sess->user) {
			buddy = evt->from;
		} else if (evt->to && evt->to != &sess->user) {
			buddy = evt->to;
		} else {
			pom_log(POM_LOG_DEBUG "Out of band event without known source or destination");
			return POM_OK;
		}
			
		struct target_connection_party_msn *party = NULL;
		for (conv = sess->conv; conv && !party; conv = conv->next)  {
			for (party = conv->parts; party && party->buddy != buddy; party = party->next);
			if (party)
				break;
		}

		if (!party || !conv) {
			pom_log(POM_LOG_TSHOOT "Corresponding conversation not found for out of band message. Creating it");

			// Create the conversation
			conv = malloc(sizeof(struct target_conversation_msn));
			memset(conv, 0, sizeof(struct target_conversation_msn));
			conv->fd = -1;
			conv->sess = sess;
			conv->refcount++;

			conv->next = sess->conv;
			if (sess->conv)
				sess->conv->prev = conv;
			sess->conv = conv;

			// Add the party
			
			party = malloc(sizeof(struct target_connection_party_msn));
			memset(party, 0, sizeof(struct target_connection_party_msn));
			party->buddy = buddy;

			conv->parts = party;


		} 

		if (!party->joined) {
			party->joined = 1;

			// Process the join event
			struct target_event_msn join_evt;
			memset(&join_evt, 0, sizeof(struct target_event_msn));
			memcpy(&join_evt.tv, &evt->tv, sizeof(struct timeval));
			join_evt.from = buddy;
			join_evt.type = msn_evt_buddy_join;
			join_evt.sess = sess;
			join_evt.conv = conv;
			if (target_msn_session_process_event(&join_evt) != POM_OK)
				return POM_ERR;
		}
	}


	struct tm tmp_time;
	localtime_r((time_t*)&evt->tv.tv_sec, &tmp_time);

	if (!(evt->type & MSN_EVT_SESSION_MASK) && (conv->fd == -1)) {

		char outstr[17];
		memset(outstr, 0, sizeof(outstr));
		// /YYYYMMDD-HH.txt
		char *format = "-%Y%m%d-%H.txt";
		strftime(outstr, sizeof(outstr), format, &tmp_time);

		char filename[NAME_MAX + 1];
		strcpy(filename, sess->parsed_path);
		strncat(filename, sess->user.account, NAME_MAX - strlen(filename));
		strncat(filename, "/", NAME_MAX - strlen(filename));
		char *party_account = NULL;
		if (conv->parts) {
			party_account = conv->parts->buddy->account;
		} else {
			pom_log(POM_LOG_DEBUG "Not enough info to open the file !");
			return POM_OK;
		}
		strncat(filename, party_account, NAME_MAX - strlen(filename));
		strncat(filename, outstr, NAME_MAX - strlen(filename));

		// Open could do the job but it's better to use the API if it changes later on
		conv->fd = target_file_open(NULL, filename, O_WRONLY | O_CREAT | O_APPEND, 0666);
		if (conv->fd == POM_ERR)
			return POM_ERR;
	}

	// Open the session logs
	

	if ((evt->type & MSN_EVT_SESSION_MASK) && (sess->fd == -1)) {

		if (!PTYPE_BOOL_GETVAL(priv->dump_session))
			return POM_OK;

		char outstr[24];
		memset(outstr, 0, sizeof(outstr));
		// session-YYYYMMDD-HH.txt
		char *format = "session-%Y%m%d-%H.txt";
		strftime(outstr, sizeof(outstr), format, &tmp_time);

		char filename[NAME_MAX + 1];
		strcpy(filename, sess->parsed_path);
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

	struct target_buddy_msn *from = evt->from;
	if (!from)
		from = &sess->user;
	switch (evt->type) {
		case msn_evt_buddy_join:
			res += target_msn_session_write(conv->fd, timestamp);
			res += target_msn_session_write(conv->fd, "User ");
			res += target_msn_session_write(conv->fd, evt->from->account);
			res += target_msn_session_write(conv->fd, " joined the conversation\n");
			break;
		case msn_evt_message:
			res += target_msn_session_write(conv->fd, timestamp);
			if (!from)
				from = &sess->user;
			res += target_msn_session_write(conv->fd, from->account);
			res += target_msn_session_write(conv->fd, ": ");
			res += target_msn_session_write(conv->fd, evt->buff);
			res += target_msn_session_write(conv->fd, "\n");
			pom_log(POM_LOG_TSHOOT "%s says : \"%s\"", from->account, evt->buff);
			break;
		case msn_evt_buddy_leave:
			res += target_msn_session_write(conv->fd, timestamp);
			if (evt->from == &sess->user) {
				res += target_msn_session_write(conv->fd, "Conversation closed by user\n");
			} else {
				res += target_msn_session_write(conv->fd, "User ");
				res += target_msn_session_write(conv->fd, evt->from->account);
				res += target_msn_session_write(conv->fd, " left the conversation\n");
			}
			break;
		case msn_evt_nudge:
			res += target_msn_session_write(conv->fd, timestamp);
			res += target_msn_session_write(conv->fd, "User ");
			res += target_msn_session_write(conv->fd, from->account);
			res += target_msn_session_write(conv->fd, " sent a nudge\n");
			break;
		case msn_evt_wink:
			res += target_msn_session_write(conv->fd, timestamp);
			res += target_msn_session_write(conv->fd, "User ");
			res += target_msn_session_write(conv->fd, from->account);
			res += target_msn_session_write(conv->fd, " sent a wink\n");
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
		case msn_evt_file_transfer_start: 
			res += target_msn_session_write(conv->fd, timestamp);
			res += target_msn_session_write(conv->fd, "File transfer started with user ");
			res += target_msn_session_write(conv->fd, evt->from->account);
			if (evt->buff) {
				res += target_msn_session_write(conv->fd, " : \"");
				res += target_msn_session_write(conv->fd, evt->buff);
				res += target_msn_session_write(conv->fd, "\"");
			}
			res += target_msn_session_write(conv->fd, "\n");
			break;
		case msn_evt_file_transfer_end: 
			res += target_msn_session_write(conv->fd, timestamp);
			res += target_msn_session_write(conv->fd, "File transfer ended with user ");
			res += target_msn_session_write(conv->fd, evt->from->account);
			if (evt->buff) {
				res += target_msn_session_write(conv->fd, " : \"");
				res += target_msn_session_write(conv->fd, evt->buff);
				res += target_msn_session_write(conv->fd, "\"");
			}
			res += target_msn_session_write(conv->fd, "\n");
			break;


		// Session events
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
		case msn_evt_user_added:
			res += target_msn_session_write(sess->fd, timestamp);
			res += target_msn_session_write(sess->fd, "User added ");
			res += target_msn_session_write(sess->fd, evt->to->account);
			res += target_msn_session_write(sess->fd, " to the buddy list\n");
			break;
		case msn_evt_user_blocked:
			res += target_msn_session_write(sess->fd, timestamp);
			res += target_msn_session_write(sess->fd, "User ");
			res += target_msn_session_write(sess->fd, evt->to->account);
			res += target_msn_session_write(sess->fd, " has been blocked\n");
			break;
		case msn_evt_user_unblocked:
			res += target_msn_session_write(sess->fd, timestamp);
			res += target_msn_session_write(sess->fd, "User ");
			res += target_msn_session_write(sess->fd, evt->to->account);
			res += target_msn_session_write(sess->fd, " has been unblocked\n");
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

		if (bud->blocked) {
			res += target_msn_session_write(sess->fd, " (blocked)");
		}

		res += target_msn_session_write(sess->fd, "\n");

		bud = bud->next;
	}

	res += target_msn_session_write(sess->fd, "--- BUDDY LIST DUMP END ---\n");

	if (res != POM_OK)
		return POM_ERR;
	
	return POM_OK;
}
