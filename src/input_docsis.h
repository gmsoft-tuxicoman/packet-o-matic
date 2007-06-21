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



#ifndef __INPUT_DOCSIS_H__
#define __INPUT_DOCSIS_H__


#include "modules_common.h"
#include "input.h"

/// The PID of the DOCSIS MPEG stream
#define DOCSIS_PID 0x1FFE

/// Length of a MPEG packet
#define MPEG_TS_LEN 188

/// Buffer to temporarily store parts of DOCSIS packets
#define TEMP_BUFF_LEN 2000

/// Private structure of the docsis input.
struct input_priv_docsis {

	int frontend_fd; ///< The fd of /dev/dvb/adapterX/frontendX.
	int demux_fd; ///< The fd of /dev/dvb/adapterX/demuxX.
	int dvr_fd; ///< The fd of /dev/dvb/adapterX/dvrX.
	unsigned char *temp_buff; ///< A small temporary buffer.
	int output_layer; ///< The type of packet we output.
	unsigned int temp_buff_len; ///< The length of our temporary buffer.
	unsigned char last_seq; ///< Last MPEG sequence in the stream used count packet loss.

	// stats stuff
	unsigned long total_packets; ///< Total packet read.
	unsigned long missed_packets; ///< Number of missed packets.
	unsigned long error_packets; ///< Number of erroneous packets.
	unsigned long invalid_packets; ///< Number of invalid packets.


};

/// Init the docsis modules
int input_init_docsis(struct input *i);

/// Open the cable interface to read from it.
int input_open_docsis(struct input *i);

/// Read packets from the DOCSIS cable interface and saves it into buffer.
int input_read_docsis(struct input *i, struct frame *f);

/// Close the cable interface.
int input_close_docsis(struct input *i);

/// Cleanup the docsis input.
int input_cleanup_docsis(struct input *i);



/// Reads an MPEG packet from the cable interface.
int input_docsis_read_mpeg_frame(unsigned char *buff, struct input_priv_docsis *p);

/// Tune to the given frequency, symbole rate and modulation.
int input_docsis_tune(struct input *i, uint32_t frequency, uint32_t symboleRate, fe_modulation_t modulation);

/// Check the validity of the MPEG stream to make sure we tuned on a DOCSIS stream.
int input_docsis_check_downstream(struct input *i);

/// Provide the capabilities of the input
int input_getcaps_docsis(struct input *i, struct input_caps *ic);

#endif

