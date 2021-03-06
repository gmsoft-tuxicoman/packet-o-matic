/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __TARGET_TAP_H__
#define __TARGET_TAP_H__

#include "modules_common.h"
#include "rules.h"

struct target_priv_tap {

	int fd;
	struct ptype *ifname;
	struct ptype *persistent;

};

int target_register_tap(struct target_reg *r);

static int target_init_tap(struct target *t);
static int target_open_tap(struct target *t);
static int target_process_tap(struct target *t, struct frame *f);
static int target_close_tap(struct target *t);
static int target_cleanup_tap(struct target *t);

#endif
