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

#ifndef __TARGET_MSN_SESSION_H__
#define __TARGET_MSN_SESSION_H__

#include "target_msn.h"

int target_msn_session_found_buddy(struct target_conntrack_priv_msn *cp, char *account, char *nick, char* group_id);
int target_msn_session_found_group(struct target_conntrack_priv_msn *cp, char *name, char *id);
int target_msn_session_found_account(struct target_conntrack_priv_msn *cp, char *account);
int target_msn_session_conv_event(struct target_conntrack_priv_msn *cp, struct target_conv_event_msn *evt);

int target_msn_session_load(struct target *t, struct target_conntrack_priv_msn *cp);
int target_msn_session_save(struct target *t, struct target_conntrack_priv_msn *cp);
#endif
