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

#ifndef __TARGET_MSN_MSGS_H__
#define __TARGET_MSN_MSGS_H__

#include "target_msn.h"

#define PNG_SIGNATURE "\211PNG\r\n\032\n"

int target_process_msg_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame*);

int target_process_mime_msmsgscontrol_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_process_mime_text_plain_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_process_mime_msnmsgrp2p_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_process_mail_invite_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_process_status_msg_msn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);

#endif
