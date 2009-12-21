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



#ifndef __INPUT_DOCSIS_H__
#define __INPUT_DOCSIS_H__


#include "modules_common.h"
#include "input.h"

/// Maximum number of DVB adapter
#define DOCSIS_MAX_ADAPT 8

/// The PID of the DOCSIS MPEG stream
#define DOCSIS_PID 0x1FFE

/// Length of a MPEG packet
#define MPEG_TS_LEN 188

/// snaplen for docsis input
#define DOCSIS_SNAPLEN 1800 // should be less but we alloc a bit more for internal processing

/// Buffer to temporarily store parts of DOCSIS packets
#define TEMP_BUFF_LEN 2000

/// Transmition time of a MPEG frame in usec assuming QAM256 and 6952000 sym/sec
#define MPEG_XMIT_TIME 188 * 1000000 / 6952000

#define DOCSIS_WARN_ENCRYPTED	0x1	///< Was encrypted traffic found and a warning issued 
#define DOCSIS_WARN_DOCSIS3	0x2	///< DOCSIS 3 stream detected

struct input_adapt_reg_docsis {

	struct ptype *adapter;
	struct ptype *frontend;

};

struct input_adapt_docsis {

	char *frontend_name; ///< Name of the frontend device
	int frontend_fd; ///< The fd of /dev/dvb/adapterX/frontendX.
	int demux_fd; ///< The fd of /dev/dvb/adapterX/demuxX.
	int dvr_fd; ///< The fd of /dev/dvb/adapterX/dvrX.
	fe_type_t frontend_type; ///< Type of the frontend (either FE_QAM or FE_ATSC)
	unsigned int freq; ///< Current frequency in Hz
	fe_modulation_t modulation; ////< Modulation to use
	unsigned char last_seq; ///< Last MPEG sequence in the stream used count packet loss.
	unsigned int packet_pos; ///< Current position in the buffer
	unsigned char *packet_buff_base; ///< Buffer for a packet
	unsigned char *packet_buff; ///< Aligned buffer for a packet
	unsigned int packet_buff_len; ///< Length of the buffer
	struct timeval packet_rcvd_time; ///< Time when the packet arrived

	struct perf_item *perf_mpeg_tot_pkts; ///< Total MPEG packet read
	struct perf_item *perf_mpeg_missed_pkts; ///< Number of missed MPEG packets
	struct perf_item *perf_mpeg_err_pkts; ///< Number of erroneous MPEG packets
	struct perf_item *perf_mpeg_invalid_pkts; ///< Number of invalid MPEG packets
	struct perf_item *perf_pkts; ///< Number of packets read
	struct perf_item *perf_bytes; ///< Number of bytes read


	struct perf_item *perf_signal; ///< Signal strength
	struct perf_item *perf_snr; ///< Signal to noise ratio
	struct perf_item *perf_ber; ///< Bit error rate
	struct perf_item *perf_unc; ///< Uncorrected blocks

	
};

/// Private structure of the docsis input.
struct input_priv_docsis {

	int output_layer; ///< The type of packet we output.

	struct input_adapt_docsis adapts[DOCSIS_MAX_ADAPT];
	unsigned int num_adapts_open; ///< Number of adapters open

	unsigned int scan_curfreq; ///< Current frequency when scanning
	unsigned int scan_step; ///< Frequency steps to use
	unsigned int scan_endfreq; ///< Frequency to stop at
	unsigned int scan_srate; ///< Symbol rate to use
	fe_modulation_t scan_modulation; ////< Modulation to use

	// variables used in mode file to compute packet arrival time
	uint32_t last_sync_tstamp;
	struct timeval packet_time, packet_time_last_sync;

	// stats stuff
	struct perf_item *perf_tot_pkts; ///< Total packet read
	struct perf_item *perf_missed_pkts; ///< Number of missed packets
	struct perf_item *perf_err_pkts; ///< Number of erroneous packets
	struct perf_item *perf_invalid_pkts; ///< Number of invalid packets

	// misc stuff
	int warning_flags; ///< Which warnings were displayed already

};

/// Register the docsis modulbe
int input_register_docsis(struct input_reg *r);

/// Init the docsis modules
static int input_init_docsis(struct input *i);

/// Open one DVB adapter
static int input_open_adapt_docsis(struct input *i, unsigned int adapt_id, int eurodocsis);

/// Open the cable interface to read from it.
static int input_open_docsis(struct input *i);

/// Scan the current frequency for a docsis stream
static int input_scan_docsis(struct input *i);

/// Read packets from the DOCSIS cable interface and saves it into buffer.
static int input_read_docsis(struct input *i, struct frame *f);

/// Read the next mpeg packet from an adapater.
static int input_read_from_adapt_docsis(struct input *i, struct frame *f, unsigned int adapt_id);

/// Close the cable interface.
static int input_close_docsis(struct input *i);

/// Cleanup the docsis input.
static int input_cleanup_docsis(struct input *i);

/// Cleanup the memory allocated at registration time
static int input_unregister_docsis(struct input_reg *r);

/// Reads an MPEG packet from the cable interface.
static int input_docsis_read_mpeg_frame(unsigned char *buff, struct input_priv_docsis *p, unsigned int adapt_id);

/// Tune to the given frequency, symbole rate and modulation.
static int input_docsis_tune(struct input_priv_docsis *p, uint32_t frequency, uint32_t symboleRate, fe_modulation_t modulation, unsigned int adapt_id);

/// Check the validity of the MPEG stream to make sure we tuned on a DOCSIS stream.
static int input_docsis_check_downstream(struct input *i, unsigned int adapt_id);

/// Parse MDD packets to find new frequencies
static int input_parse_mdd_docsis(struct input *i, unsigned int adapt_id, unsigned char *buff, unsigned int len);

/// Provide the capabilities of the input
static int input_getcaps_docsis(struct input *i, struct input_caps *ic);

/// Update signal perf gauge
static int input_update_signal_docsis(struct perf_item *itm, void *priv);

/// Update snr perf gauge
static int input_update_snr_docsis(struct perf_item *itm, void *priv);

/// Update ber perf gauge
static int input_update_ber_docsis(struct perf_item *itm, void *priv);

/// Update uncorrected block counter
static int input_update_unc_docsis(struct perf_item *itm, void *priv);

#endif

