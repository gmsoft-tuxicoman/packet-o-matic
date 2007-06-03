/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2007 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __TARGET_INJECT_H__
#define __TARGET_INJECT_H__

#include <unistd.h>
#include <string.h>
#include <libnet.h>


#include "modules_common.h"
#include "target.h"

struct target_priv_inject {

	libnet_t *lc;
	char errbuf[LIBNET_ERRBUF_SIZE];
	unsigned int size;
};

int target_init_inject(struct target *t);
int target_open_inject(struct target *t);
int target_process_inject(struct target *t, struct frame *f);
int target_close_inject(struct target *t);
int target_cleanup_inject(struct target *t);

#endif
