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

#ifndef __TARGET_MSN_SESSION_H__
#define __TARGET_MSN_SESSION_H__

#include "target_msn.h"

// Found someone currently talking
struct target_connection_party_msn *target_msn_session_found_party(struct target *t, struct target_conntrack_priv_msn *cp, char *account, char *nick, struct timeval *when);

// Get the buddy from the hash table
struct target_buddy_msn *target_msn_session_get_buddy(struct target_priv_msn *priv, char *account);

// Found someone in the buddy list
struct target_buddy_list_session_msn *target_msn_session_found_buddy(struct target_conntrack_priv_msn *cp, char *account, char *nick, char* group_list, struct timeval *when);
struct target_buddy_list_session_msn *target_msn_session_found_buddy2(struct target_conntrack_priv_msn *cp, struct target_buddy_msn *bud, char *nick, char *group_list, struct timeval *when);

// Found a group
int target_msn_session_found_group(struct target_conntrack_priv_msn *cp, char *name, char *id);

// Found the account of the user
int target_msn_session_found_account(struct target *t, struct target_conntrack_priv_msn *cp, char *account);

// Found the friendly name of the user
int target_msn_session_found_friendly_name(struct target *t, struct target_conntrack_priv_msn *cp, char *friendly_name, struct timeval *time);


struct target_session_priv_msn *target_msn_session_merge(struct target_priv_msn *priv, struct target_conntrack_priv_msn *cp, struct target_session_priv_msn *old_sess);
int target_msn_session_init_buddy_table(struct target *t);
int target_msn_session_broadcast_event(struct target_event_msn *evt);
int target_msn_buffer_event(struct target_event_msn *evt);
int target_msn_session_event(struct target_event_msn *evt);
int target_msn_session_process_event(struct target_event_msn *evt);
int target_msn_session_write(int fd, char *buff);
int target_msn_session_dump_buddy_list(struct target_conntrack_priv_msn *cp);

#endif
