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



#ifndef __INPUT_PCAP_H__
#define __INPUT_PCAP_H__


#include "modules_common.h"

#include "input.h"
#include "perf.h"

#include <pcap.h>

/// File info
struct input_priv_file_pcap {

	char *filename;
	struct timeval first_pkt;
	struct input_priv_file_pcap *next, *prev;
};

/// Private structure of the pcap input.
struct input_priv_pcap {

	pcap_t *p; ///< Pcap instance
	struct bpf_program fp; ///< Filter for pcap
	int output_layer; ///< Layer type to use

	unsigned long packets_read;

	struct input_priv_file_pcap *dir_files;
	struct input_priv_file_pcap *dir_cur_file;
	int datalink;

	struct perf_item *perf_dropped; ///< Only avail when reading from an iface
};

int input_register_pcap(struct input_reg *r);

static int input_init_pcap(struct input *i);
static int input_open_pcap(struct input *i);
static int input_read_pcap(struct input *i, struct frame *f);
static int input_unregister_pcap(struct input_reg *r);
static int input_close_pcap(struct input *i);
static int input_cleanup_pcap(struct input *i);
static int input_getcaps_pcap(struct input *i, struct input_caps *ic);
static int input_interrupt_pcap(struct input *i);
static int input_browse_dir_pcap(struct input_priv_pcap *priv);
static int input_open_next_file_pcap(struct input_priv_pcap *p);
static int input_update_dropped_pcap(struct perf_item *itm, void *priv);

#endif

