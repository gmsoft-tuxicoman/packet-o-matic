/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2009 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __TARGET_PCAP_H__
#define __TARGET_PCAP_H__


#include "modules_common.h"
#include "rules.h"

#include <pcap.h>

struct target_priv_pcap {

	pcap_dumper_t *pdump;
	pcap_t *p;
	int last_layer_type;
	unsigned long cur_size, tot_size, tot_packets_num, cur_packets_num;
	time_t split_time;
	struct ptype *snaplen;
	struct ptype *filename;
	struct ptype *prefix;
	struct ptype *layer;
	struct ptype *unbuffered;

	struct ptype *split_overwrite;
	struct ptype *split_size;
	struct ptype *split_packets;
	struct ptype *split_interval;
	unsigned long split_index, split_files_num;

	struct target_conntrack_priv_pcap *ct_privs;

	int issued_warning; ///< Make sure we warn users only once about some possible issue
};

struct target_conntrack_priv_pcap {

	struct conntrack_entry *ce;
	pcap_dumper_t *pdump;

	struct target_conntrack_priv_pcap *next;
	struct target_conntrack_priv_pcap *prev;

};

int target_register_pcap(struct target_reg *r);
static int target_init_pcap(struct target *t);
static int target_open_pcap(struct target *t);
static int target_process_pcap(struct target *t, struct frame *f);
int target_close_connection_pcap(struct target *t, struct conntrack_entry *ce, void *conntrack_priv);
static int target_close_pcap(struct target *t);
static int target_cleanup_pcap(struct target *t);



#endif
