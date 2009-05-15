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

struct target_connection_party_msn *target_msn_session_add_party(struct target_conntrack_priv_msn *cp, char *account, char *nick);
int target_msn_session_found_buddy(struct target_conntrack_priv_msn *cp, char *account, char *nick, char* group_list);
int target_msn_session_found_group(struct target_conntrack_priv_msn *cp, char *name, char *id);
int target_msn_session_found_account(struct target *t, struct target_conntrack_priv_msn *cp, char *account);
int target_msn_session_found_friendly_name(struct target_conntrack_priv_msn *cp, char *friendly_name, struct timeval *time);
struct target_session_priv_msn *target_msn_session_merge(struct target_priv_msn *priv, struct target_session_priv_msn *old_sess, struct target_session_priv_msn *new_sess);
int target_msn_session_event(struct target_conntrack_priv_msn *cp, struct target_event_msn *evt);
int target_msn_session_process_event(struct target_conntrack_priv_msn *cp, struct target_event_msn *evt);
int target_msn_session_write(int fd, char *buff);

#endif
