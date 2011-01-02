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


#ifndef __TARGET_MSN_CMDS_H__
#define __TARGET_MSN_CMDS_H__

#include "modules_common.h"
#include "target_msn.h"

#define MSN_CMD_MAX_TOKEN 10

struct target_msg_msn *msn_cmd_alloc_msg(unsigned int size, enum msn_payload_type type);


int target_msn_handler_ignore(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_ver(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_cvr(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_usr(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_xfr(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_msg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_sdg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_uum(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_ubm(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_ubn(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_prp(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_lsg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_lst(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_chg(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_png(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_qng(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_ubx(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_cal(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_joi(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_ans(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_iro(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_ack(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_nak(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_bye(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_not(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_rng(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_out(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_nln(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_iln(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_fln(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_uun(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_uux(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_gcf(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_adl(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_rml(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_fqy(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_sdc(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_snd(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_qry(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_rea(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_nfy(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_put(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_del(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_add(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_adc(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);
int target_msn_handler_rem(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);

int target_msn_handler_error(struct target *t, struct target_conntrack_priv_msn *cp, struct frame *f);

#endif
