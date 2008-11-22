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
#include "target_msn_session.h"

#include <fcntl.h>


int target_msn_session_found_buddy(struct target_conntrack_priv_msn *cp, char *account, char *nick, char *group_id) {


	if (!nick)
		nick = "Unknown";



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


	bud->nick = malloc(strlen(nick) + 1);
	strcpy(bud->nick, nick);
	

	if (group_id) {
		// Sometimes a buddy belongs to two groups, but I don't care
		char *coma = strchr(group_id, ',');
		if (coma)
			*coma = 0;

		struct target_buddy_group_msn *grp = cp->session->groups;
		while (grp) {
			if (!strcmp(grp->id, group_id)) {
				bud->group  = grp;
				break;
			}
			grp = grp->next;
		}
		if (!grp) 
			pom_log(POM_LOG_TSHOOT "Group %s not found for user %s", group_id, account);
	}

	if (bud->group)
		pom_log(POM_LOG_TSHOOT "Got buddy \"%s\" (%s) in group \"%s\"", nick, account, bud->group->name);
	else
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

int target_msn_session_found_account(struct target_conntrack_priv_msn *cp, char *account) {

	struct target_session_priv_msn *sess = cp->session;

	if (!sess->account) {
		sess->account = malloc(strlen(account) + 1);
		strcpy(sess->account, account);
		char *sc = strchr(sess->account, ';');
		if (sc)
			*sc = 0;
		pom_log(POM_LOG_TSHOOT "User account is %s", sess->account);
	} else {
		if (strcmp(sess->account, account)) {
			pom_log(POM_LOG_WARN "Warning, account missmatch for the msn connection");
			return POM_ERR;
		}
	}

	while (cp->conv_buff) {
		struct target_conv_event_msn *tmp = cp->conv_buff;
		cp->conv_buff = cp->conv_buff->next;
		if (tmp->from) {
			pom_log(POM_LOG_TSHOOT "Buffered event from %s to %s", tmp->from, account);
		} else {
			pom_log(POM_LOG_TSHOOT "Buffered event from %s to conversation", account);
		}

		target_msn_session_conv_event(cp, tmp);

		free(tmp->from);
		free(tmp->buff);
		free(tmp);
		

	}

	return POM_OK;
}


int target_msn_session_conv_event(struct target_conntrack_priv_msn *cp, struct target_conv_event_msn *evt) {

	char *account = cp->session->account;

	if (!account) { // We don't know the account, buffer this event

		pom_log(POM_LOG_TSHOOT "Session account not known yet. Buffering conversation event");
		struct target_conv_event_msn *new_evt = NULL;
		new_evt = malloc(sizeof(struct target_conv_event_msn));
		memset(new_evt, 0, sizeof(struct target_conv_event_msn));

		if (evt->from) {
			new_evt->from = malloc(strlen(evt->from) + 1);
			strcpy(new_evt->from, evt->from);
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
			struct target_conv_event_msn *tmp = cp->conv_buff;
			while (tmp->next)
				tmp = tmp->next;
			tmp->next = new_evt;
		}

		return POM_OK;
	}

	struct tm tmp_time;
	localtime_r((time_t*)&evt->tv.tv_sec, &tmp_time);

	if (cp->fd == -1) {

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
			return POM_ERR;
		}
		strncat(filename, party_account, NAME_MAX - strlen(filename));
		strncat(filename, outstr, NAME_MAX - strlen(filename));

		// Open could do the job but it's better to use the API if it changes later on
		cp->fd = target_file_open(NULL, filename, O_WRONLY | O_CREAT | O_APPEND, 0666);
	}


	char timestamp[12];
	memset(timestamp, 0, sizeof(timestamp));
	char *format = "[%H:%M:%S] ";
	strftime(timestamp, sizeof(timestamp), format, &tmp_time);

	write(cp->fd, timestamp, strlen(timestamp));
	switch (evt->type) {
		case target_conv_event_type_user_join:
			write(cp->fd, "User ", strlen("User "));
			write(cp->fd, evt->from, strlen(evt->from));
			write(cp->fd, " joined the conversation\n", strlen(" joined the conversation\n"));
			break;
		case target_conv_event_type_message:
			if (evt->from) {
				write(cp->fd, evt->from, strlen(evt->from));
			} else {
				write(cp->fd, cp->session->account, strlen(cp->session->account));
			}
			write(cp->fd, ": ", strlen(": "));
			write(cp->fd, evt->buff, strlen(evt->buff));
			write(cp->fd, "\n", strlen("\n"));

			break;
		case target_conv_event_type_user_leave:
			write(cp->fd, "User ", strlen("User "));
			write(cp->fd, evt->from, strlen(evt->from));
			write(cp->fd, " left the conversation\n", strlen(" left the conversation\n"));
			break;
	}
	

	return POM_OK;

}


int target_msn_session_load(struct target *t, struct target_conntrack_priv_msn *cp) {

	pom_log(POM_LOG_TSHOOT "Loading existing buddies from %s", cp->parsed_path);

	return POM_OK;
}

int target_msn_session_save(struct target *t, struct target_conntrack_priv_msn *cp) {

	pom_log(POM_LOG_TSHOOT "Writing buddies to file in %s", cp->parsed_path);
	return POM_OK;
}

