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


#include <pcap.h>

#include "modules_common.h"

#include "input.h"

/// Private structure of the pcap input.
struct input_priv_pcap {

	pcap_t *p; ///< Pcap instance
	struct bpf_program fp; ///< Filter for pcap
	int output_layer; ///< Layer type to use

};

int input_register_pcap(struct input_reg *r);

int input_init_pcap(struct input *i);
int input_open_pcap(struct input *i);
int input_read_pcap(struct input *i, struct frame *f);
int input_unregister_pcap(struct input_reg *r);
int input_close_pcap(struct input *i);
int input_cleanup_pcap(struct input *i);
int input_getcaps_pcap(struct input *i, struct input_caps *ic);
int input_interrupt_pcap(struct input *i);


#endif

