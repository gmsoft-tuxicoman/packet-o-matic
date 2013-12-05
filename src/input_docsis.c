/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2010 Guy Martin <gmsoft@tuxicoman.be>
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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/poll.h>

#include <sys/select.h>
#include <signal.h>

#include <linux/dvb/dmx.h>
#include <linux/dvb/frontend.h>

#include <sys/ioctl.h>
#include <errno.h>

#include <stddef.h>

#include <docsis.h>
#include "input_docsis.h"

#include "ptype_string.h"
#include "ptype_bool.h"
#include "ptype_uint32.h"


/// We use a bigger buffer size of the demux interface. This way we can cope with some burst.
#define DEMUX_BUFFER_SIZE 2097152 // 2Megs

static int match_ethernet_id, match_docsis_id, match_atm_id;

static struct input_mode *mode_normal, *mode_scan, *mode_docsis3, *mode_file;
static struct ptype *p_frequency, *p_modulation, *p_outlayer, *p_startfreq, *p_frontend_reinit, *p_tuning_timeout, *p_file, *p_validate_checksum, *p_filter_docsis3;

static struct input_adapt_reg_docsis adapts[DOCSIS_MAX_ADAPT];

/*
 * This is taken from the linux kernel.
 * This mysterious table is just the CRC of each possible byte. It can be
 * computed using the standard bit-at-a-time methods. The polynomial can
 * be seen in entry 128, 0x8408. This corresponds to x^0 + x^5 + x^12.
 * Add the implicit x^16, and you have the standard CRC-CCITT.
 */
uint16_t const crc_ccitt_table[256] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

/// Register input_docsis
int input_register_docsis(struct input_reg *r) {


	r->init = input_init_docsis;
	r->open = input_open_docsis;
	r->getcaps = input_getcaps_docsis;
	r->read = input_read_docsis;
	r->close = input_close_docsis;
	r->cleanup = input_cleanup_docsis;
	r->unregister = input_unregister_docsis;

	match_ethernet_id = match_register("ethernet");
	match_atm_id = match_register("atm");
	match_docsis_id = match_register("docsis");

	mode_normal = input_register_mode(r->type, "normal", "Tune to a given frequency");
	mode_scan = input_register_mode(r->type, "scan", "Scan for possible internet frequency");
	mode_file = input_register_mode(r->type, "file", "Read MPEG packets from a file");
	mode_docsis3 = input_register_mode(r->type, "docsis3", "Tune to multiple frequencies for DOCSIS 3");

	if (!mode_normal || !mode_scan || !mode_file || !mode_docsis3)
		return POM_ERR;

	p_frequency = ptype_alloc("uint32", "Hz");
	p_modulation = ptype_alloc("string", NULL);
	p_outlayer = ptype_alloc("string", NULL);
	p_startfreq = ptype_alloc("uint32", "Hz");
	p_frontend_reinit = ptype_alloc("bool", NULL);
	p_tuning_timeout = ptype_alloc("uint32", "seconds");
	p_file = ptype_alloc("string", NULL);
	p_validate_checksum = ptype_alloc("bool", NULL);
	p_filter_docsis3 = ptype_alloc("bool", NULL);
	
	if (!p_frequency || !p_modulation || !p_outlayer || !p_startfreq || !p_frontend_reinit || !p_tuning_timeout || !p_file || !p_validate_checksum || !p_filter_docsis3) {
		input_unregister_docsis(r);
		return POM_ERR;
	}
	

	memset(adapts, 0, sizeof(struct input_adapt_reg_docsis) * DOCSIS_MAX_ADAPT);
	int i;
	for (i = 0; i < DOCSIS_MAX_ADAPT; i++) {
		adapts[i].adapter = ptype_alloc("uint16", NULL);
		adapts[i].frontend = ptype_alloc("uint16", NULL);
		if (!adapts[i].adapter || !adapts[i].frontend) {
			input_unregister_docsis(r);
			return POM_ERR;
		}
	}

	input_register_param(mode_normal, "frequency", "440000000", p_frequency, "Frequency of the DOCSIS stream in Hz");
	input_register_param(mode_normal, "modulation", "QAM256", p_modulation, "Modulation of the DOCSIS stream");
	input_register_param(mode_normal, "adapter", "0", adapts[0].adapter, "ID of the DVB adapter to use");
	input_register_param(mode_normal, "frontend", "0", adapts[0].frontend, "ID of the DVB frontend to use for the specified adapter");
	input_register_param(mode_normal, "tuning_timeout", "3", p_tuning_timeout, "Timeout to wait until giving up when waiting for a lock");
	input_register_param(mode_normal, "outlayer", "ethernet", p_outlayer, "Type of the output layer wanted");
	input_register_param(mode_normal, "validate_checksum", "yes", p_validate_checksum, "Perform checksum validation");
	input_register_param(mode_normal, "filter_docsis3", "yes", p_filter_docsis3, "Filter out DOCSIS 3 packets from bounded streams");

	input_register_param(mode_scan, "startfreq", "0", p_startfreq, "Starting frequency in Hz. Will use the default of the specification if 0");
	input_register_param(mode_scan, "modulation", "QAM256", p_modulation, "Modulation of the DOCSIS stream");
	input_register_param(mode_scan, "adapter", "0", adapts[0].adapter, "ID of the DVB adapter to use");
	input_register_param(mode_scan, "frontend", "0", adapts[0].frontend, "ID of the DVB frontend to use for the specified adapter");
	input_register_param(mode_scan, "frontend_reinit", "no", p_frontend_reinit, "Set to yes if the frontend needs to be closed and reopened between each scan");
	input_register_param(mode_scan, "tuning_timeout", "3", p_tuning_timeout, "Timeout to wait until giving up when waiting for a lock");
	input_register_param(mode_scan, "outlayer", "ethernet", p_outlayer, "Type of the output layer wanted");
	input_register_param(mode_scan, "validate_checksum", "yes", p_validate_checksum, "Perform checksum validation");

	input_register_param(mode_docsis3, "frequency", "440000000", p_frequency, "Frequency of the DOCSIS stream in Hz");
	input_register_param(mode_docsis3, "modulation", "QAM256", p_modulation, "Modulation of the DOCSIS stream");
	input_register_param(mode_docsis3, "validate_checksum", "yes", p_validate_checksum, "Perform checksum validation");

	for (i = 0; i < DOCSIS_MAX_ADAPT; i++) {
		char adapt[] = "adapterX";
		char frontend[] = "frontendX";
		adapt[strlen(adapt) - 1] = '0' + i;
		frontend[strlen(frontend) - 1] = '0' + i;
		char id[] = "0";
		id[0] = '0' + i;
		input_register_param(mode_docsis3, adapt, id , adapts[i].adapter, "ID of the DVB adapter to use");
		input_register_param(mode_docsis3, frontend, "0", adapts[i].frontend, "ID of the DVB frontend to use for the specified adapter");

	}
	input_register_param(mode_docsis3, "tuning_timeout", "3", p_tuning_timeout, "Timeout to wait until giving up when waiting for a lock");
	input_register_param(mode_docsis3, "outlayer", "ethernet", p_outlayer, "Type of the output layer wanted");

	input_register_param(mode_file, "file",  "dump.ts", p_file, "File to read MPEG packets from");
	input_register_param(mode_file, "outlayer", "ethernet", p_outlayer, "Type of the output layer wanted");
	input_register_param(mode_file, "validate_checksum", "yes", p_validate_checksum, "Perform checksum validation");

	return POM_OK;
}

/** Always returns POM_OK. */
static int input_init_docsis(struct input *i) {

	i->input_priv = malloc(sizeof(struct input_priv_docsis));
	memset(i->input_priv, 0, sizeof(struct input_priv_docsis));

	struct input_priv_docsis *p = i->input_priv;

	int j;
	for (j = 0; j < DOCSIS_MAX_ADAPT; j++) {
		memset(&p->adapts[j], 0, sizeof(struct input_adapt_docsis));
		p->adapts[j].frontend_fd = -1;
		p->adapts[j].demux_fd = -1;
		p->adapts[j].dvr_fd = -1;
	}

	// Add counters
	p->perf_mpeg_tot_pkts = perf_add_item(i->perfs, "mpeg_tot_pkts", perf_item_type_counter, "Total number of MPEG packets for the DOCSIS PID");
	p->perf_mpeg_missed_pkts = perf_add_item(i->perfs, "mpeg_missed_pkts", perf_item_type_counter, "Number of MPEG packets lost");
	p->perf_mpeg_err_pkts = perf_add_item(i->perfs, "mpeg_err_pkts", perf_item_type_counter, "Numer of erroneous MPEG packets");
	p->perf_mpeg_invalid_pkts = perf_add_item(i->perfs, "mpeg_invalid_pkts", perf_item_type_counter, "Number of invalid MPEG packets");
	p->perf_docsis_tot_pkts = perf_add_item(i->perfs, "docsis_tot_pkts", perf_item_type_counter, "Total number of DOCSIS packets read");
	p->perf_docsis_checksum_errs = perf_add_item(i->perfs, "docsis_cksum_errs", perf_item_type_counter, "Number of packets with invalid DOCSIS checksum");

	return POM_OK;

}

/** Always returns POM_OK */
static int input_cleanup_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	int j;
	for (j = 0; j < DOCSIS_MAX_ADAPT; j++) {
		free(p->adapts[j].packet_buff_base);
	}

	free(i->input_priv);
	return POM_OK;

}

static int input_unregister_docsis(struct input_reg *r) {

	ptype_cleanup(p_frequency);
	ptype_cleanup(p_modulation);
	int i;
	for (i = 0; i < DOCSIS_MAX_ADAPT; i++) {
		if (adapts[i].adapter)
			ptype_cleanup(adapts[i].adapter);
		if (adapts[i].frontend)
			ptype_cleanup(adapts[i].frontend);
	}
	ptype_cleanup(p_outlayer);
	ptype_cleanup(p_startfreq);
	ptype_cleanup(p_frontend_reinit);
	ptype_cleanup(p_tuning_timeout);
	ptype_cleanup(p_file);
	ptype_cleanup(p_validate_checksum);
	ptype_cleanup(p_filter_docsis3);

	return POM_OK;
}


static int input_open_adapt_docsis(struct input *i, unsigned int adapt_id) {

	struct input_priv_docsis *p = i->input_priv;

	// Open the frontend
	char adapter[NAME_MAX];
	memset(adapter, 0, NAME_MAX);
	strcpy(adapter, "/dev/dvb/adapter");
	ptype_print_val(adapts[adapt_id].adapter, adapter + strlen(adapter), NAME_MAX - strlen(adapter));

	char frontend[NAME_MAX];
	strcpy(frontend, adapter);
	strcat(frontend, "/frontend");
	ptype_print_val(adapts[adapt_id].frontend, frontend + strlen(frontend), NAME_MAX - strlen(frontend));
	p->adapts[adapt_id].frontend_name = malloc(strlen(frontend) + 1);
	strcpy(p->adapts[adapt_id].frontend_name, frontend);

	p->adapts[adapt_id].frontend_fd = open(frontend, O_RDWR);
	if (p->adapts[adapt_id].frontend_fd == -1) {
		pom_log(POM_LOG_ERR "Unable to open frontend %s", frontend);
		goto err;
	}

	// Check if we are really using a DVB-C device
	
	struct dvb_frontend_info info;
	if (ioctl(p->adapts[adapt_id].frontend_fd, FE_GET_INFO, &info) != 0) {
		pom_log(POM_LOG_ERR "Unable to get frontend type for adapter %u", adapt_id);
		goto err;
	}

	if (info.type != FE_QAM && info.type != FE_ATSC) {
		pom_log(POM_LOG_ERR "Error, device %s is not a DVB-C or an ATSC device", frontend);
		goto err;
	}

	p->adapts[adapt_id].frontend_type = info.type;

	// Open the demux
	char demux[NAME_MAX];
	strcpy(demux, adapter);
	strcat(demux, "/demux0");

	p->adapts[adapt_id].demux_fd = open(demux, O_RDWR);
	if (p->adapts[adapt_id].demux_fd == -1) {
		pom_log("Unable to open demux %s", demux);
		goto err;
	}

	// Let's use a larger buffer
	if (ioctl(p->adapts[adapt_id].demux_fd, DMX_SET_BUFFER_SIZE, (unsigned long) DEMUX_BUFFER_SIZE) != 0) {
		char errbuff[256];
		strerror_r(errno, errbuff, 256);
		pom_log(POM_LOG_WARN "Unable to set the buffer size on the demux : %s", errbuff);
	}

	// Let's filter on the DOCSIS PID
	struct dmx_pes_filter_params filter;
	memset(&filter, 0, sizeof(struct dmx_pes_filter_params));	
	filter.pid = DOCSIS_PID;
	filter.input = DMX_IN_FRONTEND;
	filter.output = DMX_OUT_TS_TAP;
	filter.pes_type = DMX_PES_OTHER;
	filter.flags = DMX_IMMEDIATE_START;

	if (ioctl(p->adapts[adapt_id].demux_fd, DMX_SET_PES_FILTER, &filter) != 0) {
		pom_log(POM_LOG_ERR "Unable to set demuxer %s", demux);
		goto err;
	}

	// Let's open the dvr device

	char dvr[NAME_MAX];
	strcpy(dvr, adapter);
	strcat(dvr, "/dvr0");

	p->adapts[adapt_id].dvr_fd = open(dvr, O_RDONLY);
	if (p->adapts[adapt_id].dvr_fd == -1) {
		pom_log(POM_LOG_ERR "Unable to open dvr interface %s", dvr);
		goto err;
	}

	// Add bytes and packets counters for each interface
	if (i->mode == mode_docsis3) {
	
		char tot_pkts_str[] = "mpeg_tot_pktsX";
		tot_pkts_str[strlen(tot_pkts_str) - 1] = adapt_id + '0';
		char tot_pkts_desc[] = "Total number of MPEG packets for the DOCSIS PID on adapter X";
		tot_pkts_desc[strlen(tot_pkts_desc) - 1] = adapt_id + '0';
		p->adapts[adapt_id].perf_mpeg_tot_pkts = perf_add_item(i->perfs, tot_pkts_str, perf_item_type_counter, tot_pkts_desc);

		char missed_pkts_str[] = "mpeg_missed_pktsX";
		missed_pkts_str[strlen(missed_pkts_str) - 1] = adapt_id + '0';
		char missed_pkts_desc[] = "Number of MPEG packets lost on adapter X";
		missed_pkts_desc[strlen(missed_pkts_desc) - 1] = adapt_id + '0';
		p->adapts[adapt_id].perf_mpeg_missed_pkts = perf_add_item(i->perfs, missed_pkts_str, perf_item_type_counter, missed_pkts_desc);

		char err_pkts_str[] = "mpeg_err_pktsX";
		err_pkts_str[strlen(err_pkts_str) - 1] = adapt_id + '0';
		char err_pkts_desc[] = "Number of erroneous MPEG packets on adapter X";
		err_pkts_desc[strlen(err_pkts_desc) - 1] = adapt_id + '0';
		p->adapts[adapt_id].perf_mpeg_err_pkts = perf_add_item(i->perfs, err_pkts_str, perf_item_type_counter, err_pkts_desc);

		char invalid_pkts_str[] = "mpeg_invalid_pktsX";
		invalid_pkts_str[strlen(invalid_pkts_str) - 1] = adapt_id + '0';
		char invalid_pkts_desc[] = "Number of invalid MPEG on adapter X";
		invalid_pkts_desc[strlen(invalid_pkts_desc) - 1] = adapt_id + '0';
		p->adapts[adapt_id].perf_mpeg_invalid_pkts = perf_add_item(i->perfs, invalid_pkts_str, perf_item_type_counter, invalid_pkts_desc);

		char pkts_str[] = "docsis_pktsX";
		pkts_str[strlen(pkts_str) - 1] = adapt_id + '0';
		char pkts_desc[] = "Number of DOCSIS packets read from adapter X";
		pkts_desc[strlen(pkts_desc) - 1] = adapt_id + '0';
		p->adapts[adapt_id].perf_docsis_pkts = perf_add_item(i->perfs, pkts_str, perf_item_type_counter, pkts_desc);

		char docsis_chksum_str[] = "docsis_checksum_errsX";
		docsis_chksum_str[strlen(docsis_chksum_str) - 1] = adapt_id + '0';
		char docsis_chksum_desc[] = "Number of DOCSIS packets with checksum error from adapter X";
		docsis_chksum_desc[strlen(docsis_chksum_desc) - 1] = adapt_id + '0';
		p->adapts[adapt_id].perf_docsis_checksum_errs = perf_add_item(i->perfs, docsis_chksum_str, perf_item_type_counter, docsis_chksum_desc);

		char bytes_str[] = "bytesX";
		bytes_str[strlen(bytes_str) - 1] = adapt_id + '0';
		char bytes_desc[] = "Number of bytes read from adapter X";
		bytes_desc[strlen(bytes_desc) - 1] = adapt_id + '0';
		p->adapts[adapt_id].perf_bytes = perf_add_item(i->perfs, bytes_str, perf_item_type_counter, bytes_desc);

	}

	// This buffer will be swapped with buffers in frame structures
	// Need to add 4 bytes for alignment purposes
	int frame_len = DOCSIS_SNAPLEN + 4;
	p->adapts[adapt_id].packet_buff_base = malloc(frame_len);
	// Recalculate correct offset for the buffer as it may have been moved to skip the docsis header
	// We should not take the align_offset in account here as the ethernet header will align perfectly
	p->adapts[adapt_id].packet_buff = (void*) (((long)p->adapts[adapt_id].packet_buff_base & ~3) + 4);
	p->adapts[adapt_id].packet_buff_len = frame_len - ((long)p->adapts[adapt_id].packet_buff - (long)p->adapts[adapt_id].packet_buff_base);

	// Add signal related perf items
	char signal_str[] = "signalX";
	signal_str[strlen(signal_str) - 1] = adapt_id + '0';
	char signal_desc[] = "Signal strength on adapter X";
	signal_desc[strlen(signal_desc) - 1] = adapt_id + '0';
	p->adapts[adapt_id].perf_signal = perf_add_item(i->perfs, signal_str, perf_item_type_gauge, signal_desc);
	perf_item_set_update_hook(p->adapts[adapt_id].perf_signal, input_update_signal_docsis, &p->adapts[adapt_id]);

	char snr_str[] = "snrX";
	snr_str[strlen(snr_str) - 1] = adapt_id + '0';
	char snr_desc[] = "Signal to noise ratio on adapter X";
	snr_desc[strlen(snr_desc) - 1] = adapt_id + '0';
	p->adapts[adapt_id].perf_snr = perf_add_item(i->perfs, snr_str, perf_item_type_gauge, snr_desc);
	perf_item_set_update_hook(p->adapts[adapt_id].perf_snr, input_update_snr_docsis, &p->adapts[adapt_id]);

	char ber_str[] = "berX";
	ber_str[strlen(ber_str) - 1] = adapt_id + '0';
	char ber_desc[] = "Bit error rate on adapter X";
	ber_desc[strlen(ber_desc) - 1] = adapt_id + '0';
	p->adapts[adapt_id].perf_ber = perf_add_item(i->perfs, ber_str, perf_item_type_gauge, ber_desc);
	perf_item_set_update_hook(p->adapts[adapt_id].perf_ber, input_update_ber_docsis, &p->adapts[adapt_id]);

	char unc_str[] = "uncX";
	unc_str[strlen(unc_str) - 1] = adapt_id + '0';
	char unc_desc[] = "Uncorrected blocks on adapter X";
	unc_desc[strlen(unc_desc) - 1] = adapt_id + '0';
	p->adapts[adapt_id].perf_unc = perf_add_item(i->perfs, unc_str, perf_item_type_counter, unc_desc);
	perf_item_set_update_hook(p->adapts[adapt_id].perf_unc, input_update_unc_docsis, &p->adapts[adapt_id]);

	
	p->num_adapts_open++;

	return POM_OK;

err:

	if (p->adapts[adapt_id].frontend_fd != -1) {
		close(p->adapts[adapt_id].frontend_fd);
		p->adapts[adapt_id].frontend_fd = -1;
	}
	if (p->adapts[adapt_id].demux_fd != -1) {
		close(p->adapts[adapt_id].demux_fd);
		p->adapts[adapt_id].demux_fd = -1;
	}
	if (p->adapts[adapt_id].dvr_fd != -1) {
		close(p->adapts[adapt_id].dvr_fd);
		p->adapts[adapt_id].dvr_fd = -1;
	}
	
	if (p->adapts[adapt_id].frontend_name) {
		free(p->adapts[adapt_id].frontend_name);
		p->adapts[adapt_id].frontend_name = NULL;
	}

	if (p->adapts[adapt_id].packet_buff_base) {
		free(p->adapts[adapt_id].packet_buff_base);
		p->adapts[adapt_id].packet_buff_base = NULL;
	}

	p->adapts[adapt_id].packet_pos = 0;

	return POM_ERR;
}


/**
 * If a frequency is not specified, it will scan for a tuneable freq.
 * Returns POM_ERR on failure or a file descriptor useable with select().
 **/
static int input_open_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;

	// Select the output type
	if (!strcmp(PTYPE_STRING_GETVAL(p_outlayer), "ethernet")) {
		p->output_layer = match_ethernet_id;
	} else if (!strcmp(PTYPE_STRING_GETVAL(p_outlayer), "atm")) {
		p->output_layer = match_atm_id;
	} else if (!strcmp(PTYPE_STRING_GETVAL(p_outlayer), "docsis")) {
		p->output_layer = match_docsis_id;
	} else {
		pom_log(POM_LOG_ERR "Invalid output layer :%s", PTYPE_STRING_GETVAL(p_outlayer));
		return POM_ERR;
	}

	if (i->mode == mode_file) {
		p->adapts[0].dvr_fd = open(PTYPE_STRING_GETVAL(p_file), O_RDONLY);
		if (p->adapts[0].dvr_fd == -1) {
			pom_log(POM_LOG_ERR "Unable to open the file %s", PTYPE_STRING_GETVAL(p_file));
			return POM_ERR;
		}

		struct stat buff;
		if (fstat(p->adapts[0].dvr_fd, &buff)) {
			pom_log(POM_LOG_ERR "Unable to stat() the file %s", PTYPE_STRING_GETVAL(p_file));
			close(p->adapts[0].dvr_fd);
			p->adapts[0].dvr_fd = -1;
			return POM_ERR;
		}
		memset(&p->packet_time, 0, sizeof(struct timeval));
		p->packet_time.tv_sec = buff.st_ctime;
		memcpy(&p->packet_time_last_sync, &p->packet_time, sizeof(struct timeval));

		// This buffer will be swapped with buffers in frame structures
		// Need to add 4 bytes for alignment purposes
		int frame_len = DOCSIS_SNAPLEN + 4;
		p->adapts[0].packet_buff_base = malloc(frame_len);
		// Recalculate correct offset for the buffer as it may have been moved to skip the docsis header
		// We should not take the align_offset in account here as the ethernet header will align perfectly
		p->adapts[0].packet_buff = (void*) (((long)p->adapts[0].packet_buff_base & ~3) + 4);
		p->adapts[0].packet_buff_len = frame_len - ((long)p->adapts[0].packet_buff - (long)p->adapts[0].packet_buff_base);

		if (input_docsis_check_downstream(i, 0) == POM_ERR) {
			pom_log(POM_LOG_ERR "Could not find a SYNC packet in the file %s", PTYPE_STRING_GETVAL(p_file));
			input_close_docsis(i);
			return POM_ERR;
		}

		p->num_adapts_open = 1;

		pom_log("Docsis stream opened successfully");

	} else {

		if (input_open_adapt_docsis(i, 0) == POM_ERR)
			return POM_ERR;

		int eurodocsis = 0;
		if (p->adapts[0].frontend_type == FE_QAM)
			eurodocsis = 1;

		// Choose right symbolRate depending on modulation
		fe_modulation_t modulation;
		if (!strcmp(PTYPE_STRING_GETVAL(p_modulation), "QAM64"))
			modulation = QAM_64;
		else if (!strcmp(PTYPE_STRING_GETVAL(p_modulation), "QAM256"))
			modulation = QAM_256;
		else {
			pom_log(POM_LOG_ERR "Invalid modulation. Valid modulation are QAM64 or QAM256");
			return POM_ERR;
		}	
			
		unsigned int symbolRate;
		if (eurodocsis)
			symbolRate = 6952000;
		else if (modulation == QAM_64)
			symbolRate = 5056941;
		else // QAM_256
			symbolRate = 5360537;


		if (i->mode == mode_normal || i->mode == mode_docsis3) {
			unsigned int frequency = PTYPE_UINT32_GETVAL(p_frequency);

			if (eurodocsis && frequency < 112000000)
				frequency = 112000000;
			else if (frequency < 91000000)
					frequency = 91000000;
			if (frequency > 858000000)
				frequency = 858000000;


			int tuned = 0;

			// Frequency and modulation supplied. Tuning to that
			int try;
			for (try = 0; try < 3; try++) {
				tuned = input_docsis_tune(p, frequency, symbolRate, modulation, 0);
				if (tuned == 1)
					break;
			}
			
			if (tuned != 1) {
				pom_log(POM_LOG_ERR "Error while tuning to %uHz on adapter %u", frequency, 0);
				input_close_docsis(i);
				return POM_ERR;
			}
			if (input_docsis_check_downstream(i, 0) == POM_ERR) {
				pom_log("Error, no DOCSIS SYNC message received within timeout");
				input_close_docsis(i);
				return POM_ERR;
			}
		
			pom_log("%sDOCSIS stream locked on adapter %u with frequency %uHz with %uQAM", (eurodocsis ? "Euro" : "US"), 0, frequency, (modulation == QAM_64 ? 64 : 256));

		} else if (i->mode == mode_scan) {


			unsigned int start = PTYPE_UINT32_GETVAL(p_startfreq);

			unsigned int end, step;
			if (eurodocsis) {
				if (start < 112000000)
					start = 112000000;
				if (start > 858000000)
					start = 858000000;
				end = 858000000;
				step = 1000000;

			} else {
				if (start < 91000000)
					start = 91000000;
				if (start > 858000000)
					start = 858000000;
				end = 857000000;
				step = 1000000;
			}

			p->scan_curfreq = start;
			p->scan_step = step;
			p->scan_endfreq = end;
			p->scan_srate = symbolRate;
			p->scan_modulation = modulation;


			pom_log("Starting a scan from %umHz to %umHz", start / 1000000, end / 1000000);
			return POM_OK;
		} else {
			pom_log(POM_LOG_ERR "Invalid input mode");
			return POM_ERR;
		}


	}

	perf_item_val_reset(p->perf_mpeg_tot_pkts);
	perf_item_val_reset(p->perf_mpeg_missed_pkts);
	perf_item_val_reset(p->perf_mpeg_err_pkts);
	perf_item_val_reset(p->perf_mpeg_invalid_pkts);
	perf_item_val_reset(p->perf_docsis_checksum_errs);

	
	return POM_OK;


}


/**
 * This function will check all the field in the MPEG packet.
 * It will also make sure that we receive at least 10 DOCSIS SYNC messages in 2 seconds.
 * Returns POM_OK on success and POM_ERR on failure.
 **/

static int input_docsis_check_downstream(struct input *i, unsigned int adapt_id) {

	struct input_priv_docsis *p = i->input_priv;

	unsigned char buffer[MPEG_TS_LEN];
	int count = 0, res;
	time_t sync_start = time(NULL);

	fd_set set;
	struct timeval tv;

	while (time(NULL) - sync_start <= 2) {
		
		FD_ZERO(&set);
		FD_SET(p->adapts[adapt_id].dvr_fd, &set);
		
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		res = select(p->adapts[adapt_id].dvr_fd + 1, &set, NULL, NULL, &tv);
		
		if (res == -1) {
			char errbuff[256];
			strerror_r(errno, errbuff, 256);
			pom_log(POM_LOG_ERR "Error select() : %s", errbuff);
			break;
		} else if (res == 0) {
			pom_log(POM_LOG_ERR "Timeout while waiting for data");
			break;
		}

		res = input_docsis_read_mpeg_frame(buffer, p, adapt_id);

		switch (res) {
			case -2:
				pom_log(POM_LOG_ERR "Error while reading MPEG stream");
				return POM_ERR;
			
			case -1:
			case 0:
				continue;

			case 1: // Got PUSI
				break;
				

		}

		unsigned char mac_start = buffer[4] + 5;
		
		// We are looking for a MAC specific header and timing mac header (0xC0)
		if (buffer[mac_start] != 0xC0) 
			continue;

		// MAC_PARM = 0
		if (buffer[mac_start + 1] != 0x0)
			continue;

		// Check HSC ?
		
		// We don't care about destination and source mac
		
		// DSAP = 0
		if (buffer[mac_start + 20] != 0x0)
			continue;

		// SSAP = 0
		if (buffer[mac_start + 21] != 0x0)
			continue;

		// Control = unumbered info
		if (buffer[mac_start + 22] != 0x3)
			continue;

		// Version = 1
		if (buffer[mac_start + 23] != 0x1)
			continue;

		// Type = 1 (SYNC msg)
		if (buffer[mac_start + 24] != 0x1)
			continue;
	
		if (i->mode == mode_file) { // Save the first timestamp when reading from a file
			memcpy(&p->last_sync_tstamp, buffer + mac_start + 26, sizeof(uint32_t));
			p->last_sync_tstamp = ntohl(p->last_sync_tstamp);
			p->adapts[adapt_id].last_seq = (buffer[3] & 0xF);
			return POM_OK;
		}

		count++;

		if (count >= 10) {
			// Initialize last seen sequence
			p->adapts[adapt_id].last_seq = (buffer[3] & 0xF);
			return POM_OK;
		}
		
	} 

	pom_log(POM_LOG_DEBUG "Did not receive SYNC message within timeout");
	return POM_ERR;
}

/**
 * This function will try to obtain a lock for tune_timeout seconds.
 * Returns 0 if not tuned in, 1 on success and -1 on fatal error.
 **/
static int input_docsis_tune(struct input_priv_docsis *p, uint32_t frequency, uint32_t symbolRate, fe_modulation_t modulation, unsigned int adapt_id) {
	
	fe_status_t status;
	struct dvb_frontend_parameters frp;
	struct pollfd pfd[1];

	memset(&frp, 0, sizeof(struct dvb_frontend_parameters));
	frp.frequency = frequency;
	frp.inversion = INVERSION_AUTO; // DOCSIS explicitly prohibit inversion but we keep AUTO to play it safe
	if (p->adapts[adapt_id].frontend_type == FE_QAM) { // DVB-C card
		frp.u.qam.symbol_rate = symbolRate;
		frp.u.qam.fec_inner = FEC_AUTO;
		frp.u.qam.modulation = modulation;
	} else if (p->adapts[adapt_id].frontend_type == FE_ATSC) { // ATSC card
		frp.u.vsb.modulation = modulation;
	} else
		return -1;

	// Let's do some tuning

	if (ioctl(p->adapts[adapt_id].frontend_fd, FE_SET_FRONTEND, &frp) < 0){
		pom_log(POM_LOG_ERR "Error while setting tuning parameters");
		return -1;
	}


	pfd[0].fd = p->adapts[adapt_id].frontend_fd;
	pfd[0].events = POLLIN;

	struct timeval now;
	gettimeofday(&now, NULL);
	time_t timeout = now.tv_sec + PTYPE_UINT32_GETVAL(p_tuning_timeout);

	while (now.tv_sec < timeout) {
		if (poll(pfd, 1, 1000)){
			if (pfd[0].revents & POLLIN) {
				if (ioctl(p->adapts[adapt_id].frontend_fd, FE_READ_STATUS, &status)) {
					pom_log(POM_LOG_WARN "IOCTL failed while getting status of DOCSIS input on adapter %u", adapt_id);
					return -1;
				}
				
				if (status & FE_TIMEDOUT) {
					pom_log(POM_LOG_WARN "Timeout while tuning");
					return 0;
				}
				if (status & FE_REINIT) {
					pom_log(POM_LOG_WARN "Frontend was reinit");
					return 0;
				}
				
				char status_str[128];
				memset(status_str, 0, sizeof(status_str));
				if (status)
					strcat(status_str, "Status : " );

				if (status & FE_HAS_SIGNAL)
					strcat(status_str, "SIGNAL ");
				if (status & FE_HAS_CARRIER)
					strcat(status_str, "CARRIER ");
				if (status & FE_HAS_VITERBI)
					strcat(status_str, "VITERBI ");
				if (status & FE_HAS_SYNC)
					strcat(status_str, "VSYNC ");
				if (status & FE_HAS_LOCK)
					strcat(status_str, "LOCK ");
				if (status)
					pom_log(POM_LOG_DEBUG "%s", status_str);
				if (status & FE_HAS_LOCK) {
					p->adapts[adapt_id].freq = frequency;
					p->adapts[adapt_id].modulation = modulation;

					return 1;
				}


			} 
		} 
		gettimeofday(&now, NULL);
	}

	pom_log("Lock not aquired on adapter %u", adapt_id);

	return 0;

}

/**
 * Fill buff with an MPEG packet of MPEG_TS_LEN bytes and check it's validity.
 * Returns 0 on success, 1 if PUSI is set, -1 if it's and invalid packet, -2 if there was an error while reading and -3 on EOF
 */

static int input_docsis_read_mpeg_frame(unsigned char *buff, struct input_priv_docsis *p, unsigned int adapt_id) {
	

		// Fill the mpeg buffer
		ssize_t len = 0, r = 0;

		do {

			r = read(p->adapts[adapt_id].dvr_fd, buff + len, MPEG_TS_LEN - len);
			if (r < 0) {
				if (errno == EOVERFLOW) {
					pom_log(POM_LOG_DEBUG "Overflow in the kernel buffer while reading MPEG packets from adapter %u. Lots of packets were missed", adapt_id);
					len = 0;
					r = 0;
					// Approximation but whole buffer is being discarded in the kernel
					if (p->adapts[adapt_id].perf_mpeg_tot_pkts && p->adapts[adapt_id].perf_mpeg_missed_pkts) {
						perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_missed_pkts, DEMUX_BUFFER_SIZE / MPEG_TS_LEN);
						perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_tot_pkts, DEMUX_BUFFER_SIZE / MPEG_TS_LEN);				
					}
					perf_item_val_inc(p->perf_mpeg_missed_pkts, DEMUX_BUFFER_SIZE / MPEG_TS_LEN);
					perf_item_val_inc(p->perf_mpeg_tot_pkts, DEMUX_BUFFER_SIZE / MPEG_TS_LEN);
					continue;
				} else if (errno == EINTR) {
					pom_log(POM_LOG_DEBUG "Read interrupted by signal");
					return -3;
				}
				pom_log(POM_LOG_ERR "Error while reading dvr of adapter %u", adapt_id);
				return -2;
			} else if (r == 0) {
				return -3; // End of file
			}
			len += r;
		} while (len < MPEG_TS_LEN);


		// Let's see if we should care about that packet

		// Check for the right PID, normaly the demux handle this
		if ( ((buff[1] & 0x1F) != 0x1F) || (buff[2] != 0xFE)) {
			// Don't count packets for other PID as invalid
			//p->invalid_packets++;
			return -1;
		}
		if (p->adapts[adapt_id].perf_mpeg_tot_pkts)
			perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_tot_pkts, 1);
		perf_item_val_inc(p->perf_mpeg_tot_pkts, 1);

		// Check sync byte
		if (buff[0] != 0x47) {
			pom_log(POM_LOG_ERR "Error, stream out of sync on adapter %u ! Aborting !", adapt_id);
			return -2;
		}
		
		// Check transport error indicator
		if (buff[1] & 0x80) {
			if (p->adapts[adapt_id].perf_mpeg_err_pkts)
				perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_err_pkts, 1);
			perf_item_val_inc(p->perf_mpeg_err_pkts, 1);
			return -1;
		}
		
		// Check the transport priority
		if (buff[1] & 0x20) {
			if (p->adapts[adapt_id].perf_mpeg_invalid_pkts)
				perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_invalid_pkts, 1);
			perf_item_val_inc(p->perf_mpeg_invalid_pkts, 1);
			return -1;
		}


		// Check the transport scrambling control
		if (buff[3] & 0xC0) {
			if (p->adapts[adapt_id].perf_mpeg_invalid_pkts)
				perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_invalid_pkts, 1);
			perf_item_val_inc(p->perf_mpeg_invalid_pkts, 1);
			return -1;
		}

		// Check the adaptation field control
		if ((buff[3] & 0x30) != 0x10) {
			if (p->adapts[adapt_id].perf_mpeg_invalid_pkts)
				perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_invalid_pkts, 1);
			perf_item_val_inc(p->perf_mpeg_invalid_pkts, 1);
			return -1;
		}
	
		// Check if payload unit start indicator is present and if it is valid
		if (buff[1] & 0x40) {
			if (buff[4] > 183) {
				if (p->adapts[adapt_id].perf_mpeg_invalid_pkts)
					perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_invalid_pkts, 1);
				perf_item_val_inc(p->perf_mpeg_invalid_pkts, 1);
				return -1;
			}
			return 1;
		}

		return 0;

}

/**
 * Scan for a docsis stream on the current frequency. Change mode to normal once found or increase curfreq if not.
 * Return POM_ERR if whole range was scanned or in case of error.
 */
static int input_scan_docsis(struct input *i) {


	struct input_priv_docsis *p = i->input_priv;

	int j = p->scan_curfreq;
	p->scan_curfreq += p->scan_step;

	if (p->scan_curfreq > p->scan_endfreq) {
		return POM_ERR;
	}

	unsigned int need_reinit = PTYPE_BOOL_GETVAL(p_frontend_reinit);

	pom_log("Tuning to %u mHz ...", j / 1000000);

	int res = input_docsis_tune(p, j, p->scan_srate, p->scan_modulation, 0);
	if (res == -1)
		return POM_ERR;
	else if (res == 0) {
		if (need_reinit) {
			// Let's close and reopen the frontend to reinit it
			pom_log("Reinitializing frontend ...");
			close(p->adapts[0].frontend_fd);
			sleep(10); // Yes, stupid frontends need to be closed to lock again or result is arbitrary
			p->adapts[0].frontend_fd = open(p->adapts[0].frontend_name, O_RDWR);
			if (p->adapts[0].frontend_fd == -1) {
				pom_log(POM_LOG_ERR "Error while reopening frontend");
				return POM_ERR;
			}
		}
		return POM_OK;
	}

	pom_log("Frequency tuned. Looking up for SYNC messages ...");

	if (input_docsis_check_downstream(i, 0) == POM_ERR)
		return POM_OK;

	pom_log("Downstream acquired !");

	char *qam = "unknown";
	if (p->scan_modulation == QAM_64)
		qam = "QAM64";
	else if(p->scan_modulation == QAM_256)
		qam = "QAM256";
	pom_log("Frequency : %f mHz, Symbol rate : %u Sym/s, QAM : %s", (double) j / 1000000.0, p->scan_srate, qam);

	PTYPE_UINT32_SETVAL(p_frequency, j);

	i->mode = mode_normal;

	return POM_OK;
}

/**
 * Returns POM_OK or POM_ERR in case of fatal error.
 **/
static int input_read_docsis(struct input *i, struct frame *f) {

	int dlen = 0;
	struct input_priv_docsis *p = i->input_priv;

	if (i->mode == mode_scan) 
		return input_scan_docsis(i);


	int adapt_id = 0; // Will store from what adapter the packet comes
	int timeout = 0;

	while (dlen == 0) {

		if (i->mode == mode_docsis3) {
			fd_set rfds;
			struct timeval tv;

			FD_ZERO(&rfds);
			tv.tv_sec = 1;
			tv.tv_usec = 0;

			int j;
			int max_fd = 0;
			for (j = 0; j < p->num_adapts_open; j++) {
				FD_SET(p->adapts[j].dvr_fd, &rfds);
				if (p->adapts[j].dvr_fd > max_fd)
					max_fd = p->adapts[j].dvr_fd;
			}

		
			int res = select(max_fd + 1, &rfds, NULL, NULL, &tv);
			if (res == -1) {
				if (errno == EINTR) {
					// Signal caught
					return POM_OK;
				}
				pom_log(POM_LOG_ERR "Error on select()");
				return POM_ERR;
			} else if (res > 0) {
				timeout = 0;
				for (adapt_id = 0; adapt_id < p->num_adapts_open; adapt_id++) {
					if (FD_ISSET(p->adapts[adapt_id].dvr_fd, &rfds)) {
						dlen = input_read_from_adapt_docsis(i, f, adapt_id);

						if (!i->running)
							return POM_OK;

						if (dlen < 0) // Got an error
							return POM_ERR;

						if (dlen > 0) // Got a full packet
							break;
					}
				}
			} else {
				timeout++;
				if (timeout > 10) {
					pom_log(POM_LOG_ERR "Timeout occured while waiting for data on all adaptors");
					return POM_ERR;
				}
			}

		} else if (i->mode == mode_normal || i->mode == mode_file) {
			dlen = input_read_from_adapt_docsis(i, f, adapt_id);

			if (!i->running)
				return POM_OK;

			if (dlen < 0)
				return POM_ERR;
		}
		
	}



	// We have a full packet at this point
	

	// Reset f->buff before writing in it
	int frame_len = DOCSIS_SNAPLEN + 4;
	f->buff = (void*) (((long)f->buff_base & ~3) + 4);
	f->bufflen = frame_len - ((long)f->buff - (long)f->buff_base);

	// Temporarily put the leftovers in the frame buffer
	if (dlen < p->adapts[adapt_id].packet_pos) {
		int pos = dlen;
		// Skip stuff bytes
		while (pos < p->adapts[adapt_id].packet_pos && p->adapts[adapt_id].packet_buff[pos] == 0xff)
			pos++;
	
		int remaining = p->adapts[adapt_id].packet_pos - pos;

		memcpy(f->buff, p->adapts[adapt_id].packet_buff + pos, remaining);
		p->adapts[adapt_id].packet_pos = remaining;


		// Save arrival time of next packet
		gettimeofday(&p->adapts[adapt_id].packet_rcvd_time, NULL);

	} else {
		p->adapts[adapt_id].packet_pos = 0;
	}

	// Swap buffers
	unsigned char *buff_base = f->buff_base;
	unsigned char *buff = f->buff;
	unsigned int bufflen = f->bufflen;
	f->buff_base = p->adapts[adapt_id].packet_buff_base;
	f->buff = p->adapts[adapt_id].packet_buff;
	f->bufflen = p->adapts[adapt_id].packet_buff_len;

	p->adapts[adapt_id].packet_buff_base = buff_base;
	p->adapts[adapt_id].packet_buff = buff;
	p->adapts[adapt_id].packet_buff_len = bufflen;


	if (p->adapts[adapt_id].perf_docsis_pkts)
		perf_item_val_inc(p->adapts[adapt_id].perf_docsis_pkts, 1);
	if (p->adapts[adapt_id].perf_bytes)
		perf_item_val_inc(p->adapts[adapt_id].perf_bytes, dlen);
	perf_item_val_inc(p->perf_docsis_tot_pkts, 1);

	struct docsis_hdr *dhdr = (struct docsis_hdr*) f->buff;
	
	// Check EHDR len
	
	if (dhdr->ehdr_on) {
		if (dhdr->mac_parm > dlen) {
			pom_log(POM_LOG_TSHOOT "Invalid EHDR size in DOCSIS packet. Discarding.");
			f->len = 0;
			perf_item_val_inc(p->perf_mpeg_invalid_pkts, 1);
			return POM_OK;
		}
	}

	// Validate checksum
	
	if (PTYPE_BOOL_GETVAL(p_validate_checksum)) {
		uint16_t crc = 0xffff, crc_len = offsetof(struct docsis_hdr, hcs);
		uint8_t *crc_buff = f->buff;
		if (dhdr->ehdr_on)
			crc_len += dhdr->mac_parm;

		for (; crc_len; crc_len--)
			crc = (crc >> 8) ^ crc_ccitt_table[(crc ^ (*crc_buff++)) & 0xff];
		crc ^= 0xffff;

		if (crc != *((uint16_t*)crc_buff)) {
			f->len = 0;
			if (p->adapts[adapt_id].perf_docsis_checksum_errs)
				perf_item_val_inc(p->adapts[adapt_id].perf_docsis_checksum_errs, 1);
			perf_item_val_inc(p->perf_docsis_checksum_errs, 1);
			return POM_OK;
		}
	}

	// Check for encrypted packets

	if (dhdr->ehdr_on) {
		struct docsis_ehdr *ehdr = (struct docsis_ehdr*) (f->buff + offsetof(struct docsis_hdr, hcs));
		// EH_TYPE_BP_UP should not occur as we only support downstream
		if (ehdr->eh_type == EH_TYPE_BP_DOWN) {
			if (!(p->warning_flags & DOCSIS_WARN_ENCRYPTED)) {
				pom_log(POM_LOG_WARN "Encrypted (or corrupted) packet detected on adapter %u. You may not be able to see a lot of traffic", adapt_id);
				p->warning_flags |= DOCSIS_WARN_ENCRYPTED;
			}
			if (p->output_layer != match_docsis_id)
				return POM_OK;
		}
	}

	// Process MDD if found

	if (dhdr->fc_type == FC_TYPE_MAC_SPC && dhdr->fc_parm == FCP_MGMT) {
		struct docsis_mgmt_hdr *mgmt_hdr = f->buff + sizeof(struct docsis_hdr);
		if (ntohs(mgmt_hdr->len) + offsetof(struct docsis_mgmt_hdr, dsap) < dlen - sizeof(struct docsis_hdr)
			&& mgmt_hdr->dsap == 0 && mgmt_hdr->ssap == 0 
			&& mgmt_hdr->control == 0x03 && mgmt_hdr->type == 33
			&& mgmt_hdr->version == 4) {
				if (i->mode == mode_normal) {
					if (!(p->warning_flags & DOCSIS_WARN_DOCSIS3)) {
						pom_log(POM_LOG_WARN "DOCSIS 3 stream found. Switch this input to mode docsis3 to capture on multiple cards");
						p->warning_flags |= DOCSIS_WARN_DOCSIS3;
					input_parse_mdd_docsis(i, adapt_id, f->buff + sizeof(struct docsis_hdr) + sizeof(struct docsis_mgmt_hdr), dlen - sizeof(struct docsis_hdr) - sizeof(struct docsis_mgmt_hdr));
					}
				} else if (i->mode == mode_docsis3) {
					int res;
					res = input_parse_mdd_docsis(i, adapt_id, f->buff + sizeof(struct docsis_hdr) + sizeof(struct docsis_mgmt_hdr), dlen - sizeof(struct docsis_hdr) - sizeof(struct docsis_mgmt_hdr));
					if (res == POM_ERR)
						return POM_ERR;
				}
			}	

	}


	if (p->output_layer == match_ethernet_id || p->output_layer == match_atm_id) {

		if (p->output_layer == match_ethernet_id) {
			if (dhdr->fc_type != FC_TYPE_PKT_MAC && dhdr->fc_type != FC_TYPE_ISOLATION_PKT_MAC) {
				f->len = 0;
				return POM_OK;
			}
			if (dlen < 18) { // Minimum ethernet len
				pom_log(POM_LOG_TSHOOT "Ethernet packet too short. Discarding.");
				f->len = 0;
				return POM_OK;
			}

			// We don't need the last 4 bytes containing the ethernet checksum
			dlen -= 4;
			
			// TODO : perform checksum validation on the ethernet packet

		} else if (p->output_layer == match_atm_id) {
			if (dhdr->fc_type != FC_TYPE_ATM) {
				f->len = 0;
				return POM_OK;
			}
			if (dlen % 53) { // dlen is not a multiple of atm cell
				pom_log(POM_LOG_TSHOOT "Invalid ATM size. Discarding.");
				f->len = 0;
				return POM_OK;
			}
		}

		dlen -= sizeof(struct docsis_hdr);
		unsigned int new_start = sizeof(struct docsis_hdr);
		
		if (dhdr->ehdr_on) {

			struct docsis_ehdr *ehdr = (struct docsis_ehdr*) (f->buff + offsetof(struct docsis_hdr, hcs));
			if (i->mode == mode_normal && ehdr->eh_type == EH_TYPE_DS && ehdr->eh_len == 5 && PTYPE_BOOL_GETVAL(p_filter_docsis3)) {
				f->len = 0;
				return POM_OK;
			}
			

			new_start += dhdr->mac_parm;
			dlen -= dhdr->mac_parm;
		}

		f->buff += new_start;

	}

	if (i->mode == mode_file)
		memcpy(&f->tv, &p->packet_time, sizeof(struct timeval));
	else
		memcpy(&f->tv, &p->adapts[adapt_id].packet_rcvd_time, sizeof(struct timeval));

	f->len = dlen;
	f->first_layer = p->output_layer;
	return POM_OK;

} 

/*
 * Return -1 on error, lenght of DOCSIS packet or 0 if DOCSIS packet is incomplete.
 **/

static int input_read_from_adapt_docsis(struct input *i, struct frame *f, unsigned int adapt_id) {

	struct input_priv_docsis *p = i->input_priv;

	struct input_adapt_docsis *adapt = &p->adapts[adapt_id];

	unsigned char mpeg_buff[MPEG_TS_LEN];


	if (adapt->packet_pos == 0) { // Begining of a new packet
		if (i->mode != mode_file)
			gettimeofday(&adapt->packet_rcvd_time, NULL);
	}



	int dlen = 0; // len of the docsis MAC frame including headers

	struct docsis_hdr *dhdr = (struct docsis_hdr*) adapt->packet_buff;

	// This only works because we can only capture downstream frames
	// Upstream can have REQ frame in which then len field correspond to service id

	if (adapt->packet_pos > sizeof(struct docsis_hdr)) {

		dlen = ntohs(dhdr->len) + sizeof(struct docsis_hdr);
		
		if (dlen < sizeof(struct docsis_hdr) || dlen > adapt->packet_buff_len) {
			// Invalid packet, let's discard the whole thing
			pom_log(POM_LOG_TSHOOT "Invalid packet on adapter %u. Discarding", adapt_id);
			adapt->packet_pos = 0;
			return POM_OK;
		}

		// We've got a full packet
		if (dlen <= adapt->packet_pos)
			return dlen;

	}

	//  buffer overflow. Let's discard the whole thing
	if (adapt->packet_pos + MPEG_TS_LEN - 4 >= adapt->packet_buff_len) {
		pom_log(POM_LOG_TSHOOT "Buffer overflow on adapter %u. Discarding current packet", adapt_id);
		adapt->packet_pos = 0;
		return POM_OK;
	}

	
	int res = input_docsis_read_mpeg_frame(mpeg_buff, p, adapt_id);

	if (res == -1) { // Invalid MPEG packet. Discard it
		return POM_OK;
	}

	if (i->mode == mode_file && res == -3) { // EOF
		input_close(i);
		return POM_OK;
	}

	if (res <= -2) // Error while reading
		return POM_ERR;

	// Calculate the packet aproximate time
	if (i->mode == mode_file) {
		unsigned char mac_start = mpeg_buff[4] + 5;
		if (res == 1 &&
			mpeg_buff[mac_start] == 0xC0 &&
			mpeg_buff[mac_start + 1] == 0x0 &&
			mpeg_buff[mac_start + 22] == 0x3 &&
			mpeg_buff[mac_start + 23] == 0x1 &&
			mpeg_buff[mac_start + 24] == 0x1) {
			// We got a SYNC packet
			uint32_t new_tstamp, tstamp_diff;
			memcpy(&new_tstamp, mpeg_buff + mac_start + 26, sizeof(new_tstamp));
			new_tstamp = ntohl(new_tstamp);
			if (new_tstamp > p->last_sync_tstamp)
				tstamp_diff = new_tstamp - p->last_sync_tstamp;
			else
				tstamp_diff = p->last_sync_tstamp - new_tstamp;
			// Compute in 0.01 usec
			// A tick is 6.25usec / 64
			tstamp_diff = tstamp_diff * 625 / 6400;
			p->packet_time_last_sync.tv_usec += tstamp_diff;
			if (p->packet_time_last_sync.tv_usec >= 1000000) {
				p->packet_time_last_sync.tv_sec++;
				p->packet_time_last_sync.tv_usec -= 1000000;
			}
			memcpy(&p->packet_time, &p->packet_time_last_sync, sizeof(struct timeval));
			p->last_sync_tstamp = new_tstamp;

		} else {
			// Aproximate
			p->packet_time.tv_usec += MPEG_XMIT_TIME;
			if (p->packet_time.tv_usec >= 1000000) {
				p->packet_time.tv_sec++;
				p->packet_time.tv_usec -= 1000000;
			}
		}
	}

	// Check if we missed some packets. If so, fill the gap with 0xff
	adapt->last_seq = (adapt->last_seq + 1) & 0xF;
	while (adapt->last_seq != (mpeg_buff[3] & 0xF)) {
		adapt->last_seq = (adapt->last_seq + 1) & 0xF;
		if (p->adapts[adapt_id].perf_mpeg_tot_pkts && p->adapts[adapt_id].perf_mpeg_missed_pkts) {
			perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_missed_pkts, 1);
			perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_tot_pkts, 1);
		}
		perf_item_val_inc(p->perf_mpeg_missed_pkts, 1);
		perf_item_val_inc(p->perf_mpeg_tot_pkts, 1);
		memset(adapt->packet_buff + adapt->packet_pos, 0xff, MPEG_TS_LEN - 4); // Fill buffer with stuff byte
		adapt->packet_pos += MPEG_TS_LEN - 4;

		pom_log(POM_LOG_TSHOOT "Missed one or more packets on adapter %u", adapt_id);

		if (adapt->packet_pos + MPEG_TS_LEN - 4 >= adapt->packet_buff_len) {
			//  buffer overflow. Let's discard the whole thing
			pom_log(POM_LOG_TSHOOT "Buffer overflow while filling missing packets on adapter %u. Discarding", adapt_id);
			adapt->packet_pos = 0;

			int inc = 0;
			if (adapt->last_seq < (mpeg_buff[3] & 0xF)) {
				inc = (mpeg_buff[3] & 0xF) - adapt->last_seq;
			} else {
				inc = (mpeg_buff[3] & 0xF) + 0x10 - adapt->last_seq;
			}
			if (p->adapts[adapt_id].perf_mpeg_tot_pkts && p->adapts[adapt_id].perf_mpeg_missed_pkts) {
				perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_missed_pkts, 1);
				perf_item_val_inc(p->adapts[adapt_id].perf_mpeg_tot_pkts, 1);
			}
			perf_item_val_inc(p->perf_mpeg_missed_pkts, inc);
			perf_item_val_inc(p->perf_mpeg_tot_pkts, inc);

			adapt->last_seq = mpeg_buff[3] & 0xF;
			return POM_OK;
		}
	}



	switch (res) {

		case 0: // Packet is valid and does not contain the start of a PDU
			memcpy(adapt->packet_buff + adapt->packet_pos, mpeg_buff + 4, MPEG_TS_LEN - 4);
			adapt->packet_pos += MPEG_TS_LEN - 4;
			return POM_OK;

		case 1: { // Packet is valid and contains the start of a PDU

			unsigned int new_start = adapt->packet_pos + mpeg_buff[4];

			if (mpeg_buff[4] == 0 || new_start < sizeof(struct docsis_hdr) || dlen > new_start) {
				// Either the begining of the MAC frame is at the start of the MPEG payload
				// Either the current packet size can't contain even a docsis MAC header
				// Either the current packet size calulated size doesn't fit the gap
				// let's discard the previous frame then
				if (adapt->packet_pos > 0) {
					// We got some cruft left. Discard the current buffer
					pom_log(POM_LOG_TSHOOT "Some stuff was in the buffer of adapter %u while we were expecting a new packet. Discarding it", adapt_id);
					adapt->packet_pos = 0;
					dlen = 0;
				}

				// Skip possible stuff byte
				for (new_start = mpeg_buff[4] + 5; new_start < MPEG_TS_LEN && mpeg_buff[new_start] == 0xff; new_start++);

				memcpy(adapt->packet_buff, mpeg_buff + new_start, MPEG_TS_LEN - new_start);
				adapt->packet_pos = MPEG_TS_LEN - new_start;

				return POM_OK;
			}
			

			// Se we got part of the last and new PDU here
			// Let's copy everything, we'll move later what is part of new PDU
			
			// last packet
			memcpy(adapt->packet_buff + adapt->packet_pos, mpeg_buff + 5, MPEG_TS_LEN - 5);
			adapt->packet_pos += MPEG_TS_LEN - 5;

			return POM_OK;
		}

		default: // Should not be reached
			return POM_ERR;

	}

	if (dlen < adapt->packet_pos)
		return dlen;


	return POM_OK;

}

/**
 * Returns POM_OK on success and POM_ERR on failure.
 **/
static int input_close_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	if (!p)
		return POM_ERR;


	if (i->mode == mode_scan) {
		pom_log(POM_LOG_WARN "No DOCSIS stream found");
	} else {
		if (i->mode == mode_docsis3) {
			int j;
			for (j = 0; j < p->num_adapts_open; j++) {
			pom_log("Adaptor %u : DOCSIS %llu packets, %llu bytes, %llu invalid checksum | MPEG packet read %llu, missed %llu (%.1f%%), erroneous %llu (%.1f%%), invalid %llu (%.1f%%), total errors %llu (%.1f%%)", \
				j, \
				perf_item_val_get_raw(p->adapts[j].perf_docsis_pkts), \
				perf_item_val_get_raw(p->adapts[j].perf_bytes), \
				perf_item_val_get_raw(p->adapts[j].perf_docsis_checksum_errs), \
				perf_item_val_get_raw(p->adapts[j].perf_mpeg_tot_pkts) - perf_item_val_get_raw(p->adapts[j].perf_mpeg_missed_pkts), \
				perf_item_val_get_raw(p->adapts[j].perf_mpeg_missed_pkts), \
				100.0 / (double) perf_item_val_get_raw(p->adapts[j].perf_mpeg_tot_pkts) * (double) perf_item_val_get_raw(p->adapts[j].perf_mpeg_missed_pkts), \
				perf_item_val_get_raw(p->adapts[j].perf_mpeg_err_pkts), \
				100.0 / (double) perf_item_val_get_raw(p->adapts[j].perf_mpeg_tot_pkts) * (double) perf_item_val_get_raw(p->adapts[j].perf_mpeg_err_pkts), \
				perf_item_val_get_raw(p->adapts[j].perf_mpeg_invalid_pkts), \
				100.0 / (double) perf_item_val_get_raw(p->adapts[j].perf_mpeg_tot_pkts) * (double) perf_item_val_get_raw(p->adapts[j].perf_mpeg_invalid_pkts), \
				perf_item_val_get_raw(p->adapts[j].perf_mpeg_missed_pkts) + perf_item_val_get_raw(p->adapts[j].perf_mpeg_err_pkts) + perf_item_val_get_raw(p->adapts[j].perf_mpeg_invalid_pkts), \
				100.0 / (double) perf_item_val_get_raw(p->adapts[j].perf_mpeg_tot_pkts) * (double) (perf_item_val_get_raw(p->adapts[j].perf_mpeg_missed_pkts) + perf_item_val_get_raw(p->adapts[j].perf_mpeg_err_pkts) + perf_item_val_get_raw(p->adapts[j].perf_mpeg_invalid_pkts)));
				}
		}
		pom_log("Total : DOCSIS %llu packets, %llu (%.1f%%) invalid checksum | MPEG packet read %llu, missed %llu (%.1f%%), erroneous %llu (%.1f%%), invalid %llu (%.1f%%), total errors %llu (%.1f%%)", \
			perf_item_val_get_raw(p->perf_docsis_tot_pkts), \
			perf_item_val_get_raw(p->perf_docsis_checksum_errs), \
			100.0 / (double) perf_item_val_get_raw(p->perf_docsis_tot_pkts) * (double) perf_item_val_get_raw(p->perf_docsis_checksum_errs), \
			perf_item_val_get_raw(p->perf_mpeg_tot_pkts) - perf_item_val_get_raw(p->perf_mpeg_missed_pkts), \
			perf_item_val_get_raw(p->perf_mpeg_missed_pkts), \
			100.0 / (double) perf_item_val_get_raw(p->perf_mpeg_tot_pkts) * (double) perf_item_val_get_raw(p->perf_mpeg_missed_pkts), \
			perf_item_val_get_raw(p->perf_mpeg_err_pkts), \
			100.0 / (double) perf_item_val_get_raw(p->perf_mpeg_tot_pkts) * (double) perf_item_val_get_raw(p->perf_mpeg_err_pkts), \
			perf_item_val_get_raw(p->perf_mpeg_invalid_pkts), \
			100.0 / (double) perf_item_val_get_raw(p->perf_mpeg_tot_pkts) * (double) perf_item_val_get_raw(p->perf_mpeg_invalid_pkts), \
			perf_item_val_get_raw(p->perf_mpeg_missed_pkts) + perf_item_val_get_raw(p->perf_mpeg_err_pkts) + perf_item_val_get_raw(p->perf_mpeg_invalid_pkts), \
			100.0 / (double) perf_item_val_get_raw(p->perf_mpeg_tot_pkts) * (double) (perf_item_val_get_raw(p->perf_mpeg_missed_pkts) + perf_item_val_get_raw(p->perf_mpeg_err_pkts) + perf_item_val_get_raw(p->perf_mpeg_invalid_pkts)));

	}

	if (i->mode != mode_file) {
		
		int j;
		for (j = 0; j < DOCSIS_MAX_ADAPT; j++) {


			free(p->adapts[j].frontend_name);
			p->adapts[j].frontend_name = NULL;

			if (p->adapts[j].perf_mpeg_tot_pkts) {
				perf_remove_item(i->perfs, p->adapts[j].perf_mpeg_tot_pkts);
				p->adapts[j].perf_mpeg_tot_pkts = NULL;
			}

			if (p->adapts[j].perf_mpeg_missed_pkts) {
				perf_remove_item(i->perfs, p->adapts[j].perf_mpeg_missed_pkts);
				p->adapts[j].perf_mpeg_missed_pkts = NULL;
			}

			if (p->adapts[j].perf_mpeg_err_pkts) {
				perf_remove_item(i->perfs, p->adapts[j].perf_mpeg_err_pkts);
				p->adapts[j].perf_mpeg_err_pkts = NULL;
			}

			if (p->adapts[j].perf_mpeg_invalid_pkts) {
				perf_remove_item(i->perfs, p->adapts[j].perf_mpeg_invalid_pkts);
				p->adapts[j].perf_mpeg_invalid_pkts = NULL;
			}

			if (p->adapts[j].perf_docsis_pkts) {
				perf_remove_item(i->perfs, p->adapts[j].perf_docsis_pkts);
				p->adapts[j].perf_docsis_pkts = NULL;
			}

			if (p->adapts[j].perf_docsis_checksum_errs) {
				perf_remove_item(i->perfs, p->adapts[j].perf_docsis_checksum_errs);
				p->adapts[j].perf_docsis_checksum_errs = NULL;
			}

			if (p->adapts[j].perf_bytes) {
				perf_remove_item(i->perfs, p->adapts[j].perf_bytes);
				p->adapts[j].perf_bytes = NULL;
			}

			if (p->adapts[j].frontend_fd != -1) {
				close(p->adapts[j].frontend_fd);
				p->adapts[j].frontend_fd = -1;
			}
			
			if (p->adapts[j].demux_fd != -1) {
				close(p->adapts[j].demux_fd);
				p->adapts[j].demux_fd = -1;
			}

			if (p->adapts[j].perf_signal) {
				perf_remove_item(i->perfs, p->adapts[j].perf_signal);
				p->adapts[j].perf_signal = NULL;
			}

			if (p->adapts[j].perf_snr) {
				perf_remove_item(i->perfs, p->adapts[j].perf_snr);
				p->adapts[j].perf_snr = NULL;
			}

			if (p->adapts[j].perf_ber) {
				perf_remove_item(i->perfs, p->adapts[j].perf_ber);
				p->adapts[j].perf_ber = NULL;
			}

			if (p->adapts[j].perf_unc) {
				perf_remove_item(i->perfs, p->adapts[j].perf_unc);
				p->adapts[j].perf_unc = NULL;
			}


			p->adapts[j].freq = 0;
			p->adapts[j].modulation = 0;

		}

	}

	int j;
	for (j = 0; j < DOCSIS_MAX_ADAPT; j++) {
		if (p->adapts[j].dvr_fd != -1) {
			close(p->adapts[j].dvr_fd);
			p->adapts[j].dvr_fd = -1;
		}

		if (p->adapts[j].packet_buff_base) {
			free(p->adapts[j].packet_buff_base);
			p->adapts[j].packet_buff_base = NULL;
		}

		// Reset temporary buffer
		p->adapts[j].packet_pos = 0;
	}


	p->num_adapts_open = 0;
	p->warning_flags = 0;

	return POM_OK;

}

static int input_parse_mdd_docsis(struct input *i, unsigned int adapt_id, unsigned char *buff, unsigned int len) {


	struct input_priv_docsis *p = i->input_priv;

	struct docsis_mgmt_mdd_hdr *mdd_hdr = (struct docsis_mgmt_mdd_hdr*)buff;
	buff += sizeof(struct docsis_mgmt_mdd_hdr);

	if (mdd_hdr->frag_tot > 1 && mdd_hdr->frag_seq > 1) {
		pom_log(POM_LOG_DEBUG "Fragmented MDD not supported");
		return POM_OK;
	}

	while (len >= 2) {
		
		unsigned char tlvlen = *(buff + 1);
		if (len < tlvlen + 2)
			break;

		switch (*buff) {
			case 1: { // Downstream Channel List
				if (len < 4) // 4 = 1 tvl, 1 len 1, 1 subtlv, 1 subtlv len
					return POM_OK;

				uint32_t freq = 0;
				unsigned char modulation = 0xff;
				unsigned char pri_capable = 0;

				buff += 2;
				len -= tlvlen + 2;
				while (tlvlen > 2) {
					// Sub TLVS
					unsigned char subtlvlen = *(buff + 1);
					if (tlvlen < subtlvlen + 1)
						return POM_OK;

					unsigned char realsublen = 0;
					switch (*buff) {
						case 2: { // Frequency
							if (subtlvlen < sizeof(uint32_t))
								return POM_OK;
							uint32_t val;
							memcpy(&val, buff + 2, sizeof(val));
							freq = ntohl(val);
							realsublen = sizeof(uint32_t);
							break;
							}
						case 3:
							modulation = *(buff + 2);
							realsublen = sizeof(char);
							break;
						case 4:
							pri_capable = *(buff + 2);
							realsublen = sizeof(char);
							break;
						default: // Invalid
							realsublen = subtlvlen;
							break;

						
					}

					if (realsublen != subtlvlen)
						return POM_OK;
					tlvlen -= subtlvlen + 2;
					buff += subtlvlen + 2;

				}
				len -= tlvlen + 2;


				if (freq != 0 && modulation != 0xff) {
					modulation &= 0xf;
					fe_modulation_t adapt_modulation;
					if (modulation == 0) {
						adapt_modulation = QAM_64;
					} else if (modulation == 1) {
						adapt_modulation = QAM_256;
					} else { // Invalid
						pom_log(POM_LOG_WARN "Invalid modulation supplied in MDD");
						return POM_OK;
					}

					if (pri_capable && pri_capable != 1) {
						pom_log(POM_LOG_WARN "Invalid 'primary capable' value in MDD");
						return POM_OK;
					}


					if (i->mode == mode_docsis3) {
						// Open the new freq
						int j, found = 0;
						for (j = 0; j < p->num_adapts_open; j++) {
							if (p->adapts[j].freq == freq && p->adapts[j].modulation == adapt_modulation) {
								//pom_log(POM_LOG_TSHOOT "Adapter %u already handles frequency %uHz", j, freq);
								found = 1;
								break;
							}
						}

						if (found)
							break;


			
						// Parse frequency
			
						int adapt_id = p->num_adapts_open;
						if (input_open_adapt_docsis(i, adapt_id) == POM_ERR)
							return POM_ERR;

						if (p->adapts[0].frontend_type != p->adapts[adapt_id].frontend_type) {
							pom_log("Error adaptator %u is not the same as adaptator 0 (DVB != ATSC)");
							return POM_ERR;
						}

						int eurodocsis = 0;
						if (p->adapts[adapt_id].frontend_type == FE_QAM)
							eurodocsis = 1;

						// Choose right symbolRate depending on modulation
						unsigned int symbolRate;
						if (eurodocsis)
							symbolRate = 6952000;
						else if (adapt_modulation == QAM_64)
							symbolRate = 5056941;
						else // QAM_256
							symbolRate = 5360537;

						int tuned = 0;

						// Frequency and modulation supplied. Tuning to that
						int try;
						for (try = 0; try < 3; try++) {
							tuned = input_docsis_tune(p, freq, symbolRate, adapt_modulation, adapt_id);
							if (tuned == 1)
								break;
						}
						
						if (tuned != 1) {
							pom_log(POM_LOG_ERR "Error while tuning to %uHz on adapter %u", freq, adapt_id);
							return POM_ERR;
						}
						if (pri_capable && input_docsis_check_downstream(i, p->num_adapts_open - 1) == POM_ERR) {
							pom_log("Error, no DOCSIS SYNC message received within timeout on adapter %u for frequency %uHz", adapt_id, freq);
							return POM_ERR;
						}

						pom_log(POM_LOG_INFO "New DOCSIS stream found and aquired on %uHz (%uQAM)%s on adapter %u", freq, (adapt_modulation == QAM_64 ? 64 : 256), (pri_capable ? ", primary capable" : ""), adapt_id);
					} else {
						// Print info
						pom_log(POM_LOG_INFO "Found DOCSIS 3 frequency %uHz (%uQAM)%s", freq, (adapt_modulation == QAM_64 ? 64 : 256),(pri_capable ? ", primary capable" : ""));
					}

				}

				break;

			default:
				len -= tlvlen + 2;
				buff += tlvlen +2;
				break;


			}

		}

	}

	return POM_OK;

}

static int input_getcaps_docsis(struct input *i, struct input_caps *ic) {

	ic->snaplen = DOCSIS_SNAPLEN; /// Must be at least that high for internal processing
	if (i->mode == mode_file)
		ic->is_live = 0;
	else
		ic->is_live = 1;

	struct input_priv_docsis *p = i->input_priv;
	if (p->output_layer == match_ethernet_id)
		ic->buff_align_offset = 2;
	else
		ic->buff_align_offset = 0;

	return POM_OK;

}

static int input_update_signal_docsis(struct perf_item *itm, void *priv) {

	struct input_adapt_docsis *adapt = priv;

	uint16_t signal = 0;
	if (ioctl(adapt->frontend_fd, FE_READ_SIGNAL_STRENGTH, &signal) != 0)
		return POM_ERR;

	itm->value = signal;
	return POM_OK;
}

static int input_update_snr_docsis(struct perf_item *itm, void *priv) {

	struct input_adapt_docsis *adapt = priv;

	uint16_t snr = 0;
	if (ioctl(adapt->frontend_fd, FE_READ_SNR, &snr) != 0)
		return POM_ERR;

	itm->value = snr;
	return POM_OK;
}

static int input_update_unc_docsis(struct perf_item *itm, void *priv) {

	struct input_adapt_docsis *adapt = priv;

	uint32_t unc = 0;
	if (ioctl(adapt->frontend_fd, FE_READ_UNCORRECTED_BLOCKS , &unc) != 0)
		return POM_ERR;
	// uncorrected blocks value get cleared after polling
	itm->value += unc;
	return POM_OK;
}

static int input_update_ber_docsis(struct perf_item *itm, void *priv) {

	struct input_adapt_docsis *adapt = priv;

	uint32_t ber = 0;
	if (ioctl(adapt->frontend_fd, FE_READ_BER, &ber) != 0)
		return POM_ERR;

	itm->value = ber;
	return POM_OK;
}
