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


#include <docsis.h>
#include "input_docsis.h"

#include "ptype_string.h"
#include "ptype_bool.h"
#include "ptype_uint32.h"


/// We use a bigger buffer size of the demux interface. This way we can cope with some burst.
#define DEMUX_BUFFER_SIZE 2097152 // 2Megs

static int match_ethernet_id, match_docsis_id, match_atm_id;

static struct input_mode *mode_normal, *mode_scan, *mode_file;
static struct ptype *p_eurodocsis, *p_frequency, *p_modulation, *p_adapter, *p_frontend, *p_outlayer, *p_startfreq, *p_frontend_reinit, *p_tuning_timeout, *p_file;

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

	if (!mode_normal || !mode_scan || !mode_file)
		return POM_ERR;

	p_eurodocsis = ptype_alloc("bool", NULL);
	p_frequency = ptype_alloc("uint32", "Hz");
	p_modulation = ptype_alloc("string", NULL);
	p_adapter = ptype_alloc("uint16", NULL);
	p_frontend = ptype_alloc("uint16", NULL);
	p_outlayer = ptype_alloc("string", NULL);
	p_startfreq = ptype_alloc("uint32", "Hz");
	p_frontend_reinit = ptype_alloc("bool", NULL);
	p_tuning_timeout = ptype_alloc("uint32", "seconds");
	p_file = ptype_alloc("string", NULL);
	
	if (!p_eurodocsis || !p_frequency || !p_modulation || !p_adapter || !p_frontend || !p_outlayer || !p_startfreq || !p_frontend_reinit || !p_tuning_timeout || !p_file) {
		input_unregister_docsis(r);
		return POM_ERR;
	}
	
	input_register_param(mode_normal, "eurodocsis", "yes", p_eurodocsis, "Use EuroDOCSIS specification instead of normal DOCSIS specification");
	input_register_param(mode_normal, "frequency", "440000000", p_frequency, "Frequency of the DOCSIS stream in Hz");
	input_register_param(mode_normal, "modulation", "QAM256", p_modulation, "Modulation of the DOCSIS stream");
	input_register_param(mode_normal, "adapter", "0", p_adapter, "ID of the DVB adapter to use");
	input_register_param(mode_normal, "frontend", "0", p_frontend, "ID of the DVB frontend to use for the specified adapter");
	input_register_param(mode_normal, "tuning_timeout", "3", p_tuning_timeout, "Timeout to wait until giving up when waiting for a lock");
	input_register_param(mode_normal, "outlayer", "ethernet", p_outlayer, "Type of the output layer wanted");

	input_register_param(mode_scan, "eurodocsis", "yes", p_eurodocsis, "Use EuroDOCSIS specification instead of normal DOCSIS specification");
	input_register_param(mode_scan, "startfreq", "0", p_startfreq, "Starting frequency in Hz. Will use the default of the specification if 0");
	input_register_param(mode_scan, "modulation", "QAM256", p_modulation, "Modulation of the DOCSIS stream");
	input_register_param(mode_scan, "adapter", "0", p_adapter, "ID of the DVB adapter to use");
	input_register_param(mode_scan, "frontend", "0", p_frontend, "ID of the DVB frontend to use for the specified adapter");
	input_register_param(mode_scan, "frontend_reinit", "no", p_frontend_reinit, "Set to yes if the frontend needs to be closed and reopened between each scan");
	input_register_param(mode_scan, "tuning_timeout", "3", p_tuning_timeout, "Timeout to wait until giving up when waiting for a lock");
	input_register_param(mode_scan, "outlayer", "ethernet", p_outlayer, "Type of the output layer wanted");

	input_register_param(mode_file, "file",  "dump.ts", p_file, "File to read MPEG packets from");
	input_register_param(mode_file, "outlayer", "ethernet", p_outlayer, "Type of the output layer wanted");



	return POM_OK;
}

/** Always returns POM_OK. */
static int input_init_docsis(struct input *i) {

	i->input_priv = malloc(sizeof(struct input_priv_docsis));
	memset(i->input_priv, 0, sizeof(struct input_priv_docsis));

	struct input_priv_docsis *p = i->input_priv;
	p->temp_buff = malloc(TEMP_BUFF_LEN);
	memset(p->temp_buff, 0xff, TEMP_BUFF_LEN);

	return POM_OK;

}

/** Always returns POM_OK */
static int input_cleanup_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	free(p->temp_buff);
	free(i->input_priv);

	return POM_OK;

}

static int input_unregister_docsis(struct input_reg *r) {

	ptype_cleanup(p_eurodocsis);
	ptype_cleanup(p_frequency);
	ptype_cleanup(p_modulation);
	ptype_cleanup(p_adapter);
	ptype_cleanup(p_frontend);
	ptype_cleanup(p_outlayer);
	ptype_cleanup(p_startfreq);
	ptype_cleanup(p_frontend_reinit);
	ptype_cleanup(p_tuning_timeout);
	ptype_cleanup(p_file);

	return POM_OK;
}

/**
 * If a frequency is not specified, it will scan for a tuneable freq.
 * Returns POM_ERR on failure or a file descriptor useable with select().
 **/
static int input_open_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	struct dmx_pes_filter_params filter;


	// Select the output type
	if (!strcmp(PTYPE_STRING_GETVAL(p_outlayer), "ethernet")) {
		p->output_layer = match_ethernet_id;
	} else if (!strcmp(PTYPE_STRING_GETVAL(p_outlayer), "atm")) {
		p->output_layer = match_atm_id;
	} else if (!strcmp(PTYPE_STRING_GETVAL(p_outlayer), "docsis")) {
		p->output_layer = match_docsis_id;
	} else {
		pom_log(POM_LOG_ERR "Invalid output layer :%s", PTYPE_STRING_GETVAL(p_outlayer));
		goto err;
	}

	if (i->mode == mode_file) {
		p->dvr_fd = open(PTYPE_STRING_GETVAL(p_file), O_RDONLY);
		if (p->dvr_fd == -1) {
			pom_log(POM_LOG_ERR "Unable to open the file %s", PTYPE_STRING_GETVAL(p_file));
			return POM_ERR;
		}

		struct stat buff;
		if (fstat(p->dvr_fd, &buff)) {
			pom_log(POM_LOG_ERR "Unable to stat() the file %s", PTYPE_STRING_GETVAL(p_file));
			close(p->dvr_fd);
			return POM_ERR;
		}
		memset(&p->packet_time, 0, sizeof(struct timeval));
		p->packet_time.tv_sec = buff.st_ctime;
		memcpy(&p->packet_time_last_sync, &p->packet_time, sizeof(struct timeval));

		if (input_docsis_check_downstream(i) == POM_ERR) {
			pom_log(POM_LOG_ERR "Could not find a SYNC packet in the file %s", PTYPE_STRING_GETVAL(p_file));
			return POM_ERR;
		}

	} else {
		// Parse eurodocsis and frequency
		int eurodocsis = PTYPE_BOOL_GETVAL(p_eurodocsis);
		unsigned int frequency = PTYPE_UINT32_GETVAL(p_frequency);

		if (eurodocsis && frequency < 112000000)
			frequency = 112000000;
		else if (frequency < 91000000)
				frequency = 91000000;
		if (frequency > 858000000)
			frequency = 858000000;

		fe_modulation_t modulation;
		if (!strcmp(PTYPE_STRING_GETVAL(p_modulation), "QAM64"))
			modulation = QAM_64;
		else if (!strcmp(PTYPE_STRING_GETVAL(p_modulation), "QAM256"))
			modulation = QAM_256;
		else {
			pom_log(POM_LOG_ERR "Invalid modulation. Valid modulation are QAM64 or QAM256");
			goto err;
		}	
		
		// Open the frontend
		char adapter[NAME_MAX];
		memset(adapter, 0, NAME_MAX);
		strcpy(adapter, "/dev/dvb/adapter");
		ptype_print_val(p_adapter, adapter + strlen(adapter), NAME_MAX - strlen(adapter));

		char frontend[NAME_MAX];
		strcpy(frontend, adapter);
		strcat(frontend, "/frontend");
		ptype_print_val(p_frontend, frontend + strlen(frontend), NAME_MAX - strlen(frontend));
		p->frontend_name = malloc(strlen(frontend) + 1);
		strcpy(p->frontend_name, frontend);

		p->frontend_fd = open(frontend, O_RDWR);
		if (p->frontend_fd == -1) {
			pom_log(POM_LOG_ERR "Unable to open frontend %s", frontend);
			goto err;
		}

		// Check if we are really using a DVB-C device
		
		struct dvb_frontend_info info;
		if (ioctl(p->frontend_fd, FE_GET_INFO, &info) != 0) {
			pom_log(POM_LOG_ERR "Unable to get frontend type");
			goto err;
		}

		if (info.type != FE_QAM && info.type != FE_ATSC) {
			pom_log(POM_LOG_ERR "Error, device %s is not a DVB-C or an ATSC device", frontend);
			goto err;
		}

		if (info.type == FE_ATSC && eurodocsis) {
			pom_log(POM_LOG_ERR "Error, EuroDOCSIS is not supported with ATSC cards");
			goto err;
		}

		p->frontend_type = info.type;

		// Open the demux
		char demux[NAME_MAX];
		strcpy(demux, adapter);
		strcat(demux, "/demux0");

		p->demux_fd = open(demux, O_RDWR);
		if (p->demux_fd == -1) {
			pom_log("Unable to open demux");
			goto err;
		}

		// Let's use a larger buffer
		if (ioctl(p->demux_fd, DMX_SET_BUFFER_SIZE, (unsigned long) DEMUX_BUFFER_SIZE) != 0) {
			char errbuff[256];
			strerror_r(errno, errbuff, 256);
			pom_log(POM_LOG_WARN "Unable to set the buffer size on the demux : %s", errbuff);
		}

		// Let's filter on the DOCSIS PID
		memset(&filter, 0, sizeof(struct dmx_pes_filter_params));	
		filter.pid = DOCSIS_PID;
		filter.input = DMX_IN_FRONTEND;
		filter.output = DMX_OUT_TS_TAP;
		filter.pes_type = DMX_PES_OTHER;
		filter.flags = DMX_IMMEDIATE_START;

		if (ioctl(p->demux_fd, DMX_SET_PES_FILTER, &filter) != 0) {
			pom_log(POM_LOG_ERR "Unable to set demuxer");
			goto err;
		}

		// Let's open the dvr device

		char dvr[NAME_MAX];
		strcpy(dvr, adapter);
		strcat(dvr, "/dvr0");

		p->dvr_fd = open(dvr, O_RDONLY);
		if (p->dvr_fd == -1) {
			pom_log(POM_LOG_ERR "Unable to open dvr interface");
			goto err;
		}


		// Choose right symbolRate depending on modulation
		unsigned int symbolRate;
		if (eurodocsis)
			symbolRate = 6952000;
		else if (modulation == QAM_64)
			symbolRate = 5056941;
		else // QAM_256
			symbolRate = 5360537;

		int tuned = 0;

		// Frequency and modulation supplied. Tuning to that
		if (i->mode == mode_normal) {
			int try;
			for (try = 0; try < 3; try++) {
				tuned = input_docsis_tune(i, frequency, symbolRate, modulation);
				if (tuned == 1)
					break;
			}
			
			if (tuned != 1) {
				pom_log(POM_LOG_ERR "Error while tuning to the right freq");
				goto err;
			}
			if (input_docsis_check_downstream(i) == POM_ERR) {
				pom_log("Error, no DOCSIS SYNC message received within timeout");
				goto err;
			}

		} else if (i->mode == mode_scan) { // No frequency supplied. Scanning for downstream


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




			pom_log("Starting a scan from %uMhz to %uMhz", start / 1000000, end / 1000000);
			return POM_OK;
		} else {
			pom_log(POM_LOG_ERR "Invalid input mode");
			goto err;
		}

		if (!tuned) {
			pom_log(POM_LOG_ERR "Failed to open docsis input");
			goto err;
		}

	}

	pom_log("Docsis stream opened successfully");
	
	return POM_OK;

err:

	close(p->frontend_fd);
	close(p->demux_fd);
	close(p->dvr_fd);
	
	return POM_ERR;

}


/**
 * This function will check all the field in the MPEG packet.
 * It will also make sure that we receive at least 10 DOCSIS SYNC messages in 2 seconds.
 * Returns POM_OK on success and POM_ERR on failure.
 **/

static int input_docsis_check_downstream(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;

	unsigned char buffer[MPEG_TS_LEN];
	int count = 0, res;
	time_t sync_start = time(NULL);

	fd_set set;
	struct timeval tv;

	while (time(NULL) - sync_start <= 2) {
		
		FD_ZERO(&set);
		FD_SET(p->dvr_fd, &set);
		
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		res = select(p->dvr_fd + 1, &set, NULL, NULL, &tv);
		
		if (res == -1) {
			char errbuff[256];
			strerror_r(errno, errbuff, 256);
			pom_log(POM_LOG_ERR "Error select() : %s", errbuff);
			break;
		} else if (res == 0) {
			pom_log(POM_LOG_ERR "Timeout while waiting for data");
			break;
		}

		res = input_docsis_read_mpeg_frame(buffer, p);

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
			p->last_seq = (buffer[3] & 0xF);
			return POM_OK;
		}

		count++;

		if (count >= 10) {
			// Initialize last seen sequence
			p->last_seq = (buffer[3] & 0xF);
			return POM_OK;
		}
		
	} 

	pom_log(POM_LOG_ERR "Did not receive SYNC message within timeout");
	return POM_ERR;
}

/**
 * This function will try to obtain a lock for tune_timeout seconds.
 * Returns 0 if not tuned in, 1 on success and -1 on fatal error.
 **/
static int input_docsis_tune(struct input *i, uint32_t frequency, uint32_t symbolRate, fe_modulation_t modulation) {
	
	fe_status_t status;
	struct dvb_frontend_parameters frp;
	struct dvb_frontend_event event;


	struct pollfd pfd[1];

	struct input_priv_docsis *p = i->input_priv;


	memset(&frp, 0, sizeof(struct dvb_frontend_parameters));
	frp.frequency = frequency;
	frp.inversion = INVERSION_AUTO; // DOCSIS explicitly prohibit inversion but we keep AUTO to play it safe
	if (p->frontend_type == FE_QAM) { // DVB-C card
		frp.u.qam.symbol_rate = symbolRate;
		frp.u.qam.fec_inner = FEC_AUTO;
		frp.u.qam.modulation = modulation;
	} else if (p->frontend_type == FE_ATSC) { // ATSC card
		frp.u.vsb.modulation = modulation;
	} else
		return -1;

	// Let's do some tuning

	if (ioctl(p->frontend_fd, FE_SET_FRONTEND, &frp) < 0){
		pom_log(POM_LOG_ERR "Error while setting tuning parameters");
		return -1;
	}


	pfd[0].fd = p->frontend_fd;
	pfd[0].events = POLLIN;

	struct timeval now;
	gettimeofday(&now, NULL);
	time_t timeout = now.tv_sec + PTYPE_UINT32_GETVAL(p_tuning_timeout);

	while (now.tv_sec < timeout) {
		if (poll(pfd, 1, 1000)){
			if (pfd[0].revents & POLLIN) {
				if (ioctl(p->frontend_fd, FE_GET_EVENT, &event)) {
					pom_log(POM_LOG_WARN "IOCTL failed while getting event of DOCSIS input");
					continue;
				}
				if (ioctl(p->frontend_fd, FE_READ_STATUS, &status)) {
					pom_log(POM_LOG_WARN "IOCTL failed while getting status of DOCSIS input");
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
				if (status & FE_HAS_LOCK)
					return 1;


			} 
		} 
		gettimeofday(&now, NULL);
	}

	pom_log("Lock not aquired");

	return 0;

}

/**
 * Fill buff with an MPEG packet of MPEG_TS_LEN bytes and check it's validity.
 * Returns 0 on success, 1 if PUSI is set, -1 if it's and invalid packet, -2 if there was an error while reading and -3 on EOF
 */

static int input_docsis_read_mpeg_frame(unsigned char *buff, struct input_priv_docsis *p) {
	

		// Fill the mpeg buffer
		size_t len = 0, r = 0;

		do {
			r = read(p->dvr_fd, buff + len, MPEG_TS_LEN - len);
			if (r < 0) {
				pom_log(POM_LOG_ERR "Error while reading dvr");
				return -2;
			} else if (r == 0) {
				return -3; // End of file
			}
			len += r;
		} while (len < MPEG_TS_LEN);

		p->total_packets++;

		// Let's see if we should care about that packet

		// Check sync byte
		if (buff[0] != 0x47) {
			pom_log(POM_LOG_ERR "Error, stream out of sync ! Abording !");
			return -2;
		}
		
		// Check transport error indicator
		if (buff[1] & 0x80) {
			p->error_packets++;
			return -1;
		}
		
		// Check the transport priority
		if (buff[1] & 0x20) {
			p->invalid_packets++;
			return -1;
		}

		// Check for the right PID, normaly the demux handle this
		if ( ((buff[1] & 0x1F) != 0x1F) && (buff[2] != 0xFE)) {
			p->invalid_packets++;
			return -1;
		}

		// Check the transport scrambling control
		if (buff[3] & 0xC0) {
			p->invalid_packets++;
			return -1;
		}

		// Check the adaptation field control
		if ((buff[3] & 0x30) != 0x10) {
			p->invalid_packets++;
			return -1;
		}
	
		// Check if payload unit start indicator is present and if it is valid
		if (buff[1] & 0x40) {
			if (buff[4] > 183) {
				p->invalid_packets++;
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
		pom_log(POM_LOG_WARN "No DOCSIS stream found");
		return POM_ERR;
	}

	unsigned int need_reinit = PTYPE_BOOL_GETVAL(p_frontend_reinit);

	pom_log("Tuning to %u Mhz ...", j / 1000000);

	int res = input_docsis_tune(i, j, p->scan_srate, p->scan_modulation);
	if (res == -1)
		return POM_ERR;
	else if (res == 0) {
		if (need_reinit) {
			// Let's close and reopen the frontend to reinit it
			pom_log("Reinitializing frontend ...");
			close(p->frontend_fd);
			sleep(10); // Yes, stupid frontends need to be closed to lock again or result is arbitrary
			p->frontend_fd = open(p->frontend_name, O_RDWR);
			if (p->frontend_fd == -1) {
				pom_log(POM_LOG_ERR "Error while reopening frontend");
				return POM_ERR;
			}
		}
		return POM_OK;
	}

	pom_log("Frequency tuned. Looking up for SYNC messages ...");

	if (input_docsis_check_downstream(i) == POM_ERR)
		return POM_OK;

	pom_log("Downstream acquired !");

	char *qam = "unknown";
	if (p->scan_modulation == QAM_64)
		qam = "QAM64";
	else if(p->scan_modulation == QAM_256)
		qam = "QAM256";
	pom_log("Frequency : %f Mhz, Symbol rate : %u Sym/s, QAM : %s", (double) j / 1000000.0, p->scan_srate, qam);

	PTYPE_UINT32_SETVAL(p_frequency, j);

	i->mode = mode_normal;

	return POM_OK;
}

/**
 * Returns POM_OK or POM_ERR in case of fatal error.
 **/
static int input_read_docsis(struct input *i, struct frame *f) {

	if (i->mode == mode_scan)
		return input_scan_docsis(i);

	struct input_priv_docsis *p = i->input_priv;

	f->first_layer = p->output_layer;

	unsigned int packet_pos = 0; // Current position in the resulting packet
	unsigned char mpeg_buff[MPEG_TS_LEN];

	struct timeval now;
	if (i->mode != mode_file)
		gettimeofday(&now, NULL);


	int dlen = 0; // len of the docsis MAC frame including headers

	// Recalculate correct offset for the buffer as it may have been moved to skip the docsis header
	// We should not take the align_offset in account here as the ethernet header will align perfectly
	int frame_len = DOCSIS_SNAPLEN + 4;
	f->buff = (void*) (((long)f->buff_base & ~3) + 4);
	f->bufflen = frame_len - ((long)f->buff - (long)f->buff_base);
	

	// Copy leftover into current buffer
	if (p->temp_buff_len > 0) {

		int pos = 0;

		// Skip stuff bytes
		while (pos < p->temp_buff_len && p->temp_buff[pos] == 0xff)
			pos++;

		memcpy(f->buff, p->temp_buff + pos, p->temp_buff_len - pos);
		packet_pos = p->temp_buff_len - pos;

		// We don't need anything from the temp buffer now
		p->temp_buff_len = 0;
	
	}

	
	struct docsis_hdr *dhdr = (struct docsis_hdr*) f->buff;

	// This only works because we can only capture downstream frames
	// Upstream can have REQ frame in which then len field correspond to service id
	while (1) {

		if (packet_pos > sizeof(struct docsis_hdr)) {

			dlen = ntohs(dhdr->len) + sizeof(struct docsis_hdr);
			
			if (dlen < sizeof(struct docsis_hdr) || dlen > f->bufflen) {
				// Invalid packet, let's discard the whole thing
				pom_log(POM_LOG_TSHOOT "Invalid packet. Discarding.");
				packet_pos = 0;
				dlen = 0;
				continue;
			}

			// We've got a full packet
			if (dlen <= packet_pos)
				break;

		}

		//  buffer overflow. Let's discard the whole thing
		if (packet_pos + MPEG_TS_LEN - 4 >= f->bufflen) {
			pom_log(POM_LOG_TSHOOT "Buffer overflow. Discarding current packet.");
			packet_pos = 0;
			dlen = 0;
		}

		int res = input_docsis_read_mpeg_frame(mpeg_buff, p);

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
		p->last_seq = (p->last_seq + 1) & 0xF;
		while (p->last_seq != (mpeg_buff[3] & 0xF)) {
			p->last_seq = (p->last_seq + 1) & 0xF;
			p->missed_packets++;
			p->total_packets++;
			memset(f->buff + packet_pos, 0xff, MPEG_TS_LEN - 4); // Fill buffer with stuff byte
			packet_pos += MPEG_TS_LEN - 4;

			pom_log(POM_LOG_TSHOOT "Missed one or more packets.");

			if (packet_pos + MPEG_TS_LEN - 4 >= f->bufflen) {
				//  buffer overflow. Let's discard the whole thing
				pom_log(POM_LOG_TSHOOT "Buffer overflow while filling missing packets. Discarding.");
				packet_pos = 0;
				dlen = 0;

				if (p->last_seq < (mpeg_buff[3] & 0xF)) {
					int inc = (mpeg_buff[3] & 0xF) - p->last_seq;
					p->missed_packets += inc;
					p->total_packets += inc;
				} else {
					int inc = (mpeg_buff[3] & 0xF) + 0x10 - p->last_seq;
					p->missed_packets += inc;
					p->total_packets += inc;
				}

				p->last_seq = mpeg_buff[3] & 0xF;
				break;
			}
		}



		switch (res) {
			case -1: // Invalid MPEG packet
				pom_log(POM_LOG_TSHOOT "Invalid packet received, filling with stuff bytes");
				memset(f->buff + packet_pos, 0xff, MPEG_TS_LEN - 4); // Fill buffer with stuff byte
				packet_pos += MPEG_TS_LEN - 4;
				continue;

			case 0: // Packet is valid and does not contain the start of a PDU
				memcpy(f->buff + packet_pos, mpeg_buff + 4, MPEG_TS_LEN - 4);
				packet_pos += MPEG_TS_LEN - 4;
				continue;

			case 1: { // Packet is valid and contains the start of a PDU

				unsigned int new_start = packet_pos + mpeg_buff[4];

				if (mpeg_buff[4] == 0 || new_start < sizeof(struct docsis_hdr) || dlen > new_start) {
					// Either the begining of the MAC frame is at the start of the MPEG payload
					// Either the current packet size can't contain even a docsis MAC header
					// Either the current packet size calulated size doesn't fit the gap
					// let's discard the previous frame then
					if (packet_pos > 0) {
						// We got some cruft left. Discard the current buffer
						pom_log(POM_LOG_TSHOOT "Some stuff was in the buffer while we were expecting a new packet. Discarding it.");
						packet_pos = 0;
					}

					// Skip possible stuff byte
					for (new_start = mpeg_buff[4] + 5; new_start < MPEG_TS_LEN && mpeg_buff[new_start] == 0xff; new_start++)
						pom_log(POM_LOG_TSHOOT "Skipped stuff byte at begining of new packet");

					memcpy(f->buff, mpeg_buff + new_start, MPEG_TS_LEN - new_start);
					packet_pos = MPEG_TS_LEN - new_start;

					continue;
				}
				

				// Se we got part of the last and new PDU here
				// Let's copy everything, we'll later what is part of new PDU
				
				// last packet
				memcpy(f->buff + packet_pos, mpeg_buff + 5, MPEG_TS_LEN - 5);
				packet_pos += MPEG_TS_LEN - 5;

				continue;
			}

			default: // Should not be reached
				return POM_ERR;

		}


	}
	// We have a full packet !

	if (dlen < packet_pos) { // Copy leftover if any
		memcpy(p->temp_buff, f->buff + dlen, packet_pos - dlen);
		p->temp_buff_len = packet_pos - dlen;
	} 


	if (p->output_layer == match_ethernet_id || p->output_layer == match_atm_id) {

		if (p->output_layer == match_ethernet_id) {
			if (dhdr->fc_type != FC_TYPE_PKT_MAC) {
				f->len = 0;
				return POM_OK;
			}
			if (dlen < 64) { // Minimum ethernet len
				pom_log(POM_LOG_TSHOOT "Ethernet packet too short. Discarding.");
				f->len = 0;
				return POM_OK;
			}

			// We don't need the last 4 bytes containing the ethernet checksum
			dlen -= 4;
		} else if (p->output_layer == match_atm_id) {
			if (dhdr->fc_type != FC_TYPE_ATM) {
				f->len = 0;
				return POM_OK;
			}
			if (dlen % 53) { // dlen is not a multiple of atm cell
				pom_log(POM_LOG_TSHOOT "Invalid ATM size. Discarding.");
				f->len = 0;
			}
			return POM_OK;
		}

		dlen -= sizeof(struct docsis_hdr);
		unsigned int new_start = sizeof(struct docsis_hdr);
		
		// fc_parm is len of ehdr if ehdr_on == 1
		if (dhdr->ehdr_on) {
			new_start += dhdr->fc_parm;
			dlen -= new_start;
		}

		f->buff += new_start;

	}

	if (i->mode == mode_file)
		memcpy(&f->tv, &p->packet_time, sizeof(struct timeval));
	else
		memcpy(&f->tv, &now, sizeof(struct timeval));
	
	f->len = dlen;
	return POM_OK;

}

/**
 * Returns POM_OK on success and POM_ERR on failure.
 **/
static int input_close_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	if (!p)
		return POM_ERR;

	if (i->mode != mode_file) {
		free(p->frontend_name);
		p->frontend_name = 0;

		close(p->frontend_fd);
		close(p->demux_fd);
	}

	close(p->dvr_fd);

	pom_log("0x%02lx; DOCSIS : Total MPEG packet read %lu, missed %lu (%.1f%%), erroneous %lu (%.1f%%), invalid %lu (%.1f%%), total errors %lu (%.1f%%)", \
		(unsigned long) i->input_priv, \
		p->total_packets - p->missed_packets, \
		p->missed_packets, \
		100.0 / (double) p->total_packets * (double) p->missed_packets, \
		p->error_packets, \
		100.0 / (double) p->total_packets * (double) p->error_packets, \
		p->invalid_packets, \
		100.0 / (double) p->total_packets * (double) p->invalid_packets, \
		p->missed_packets + p->error_packets + p->invalid_packets, \
		100.0 / (double) p->total_packets * (double) (p->missed_packets  + p->error_packets + p->invalid_packets));

	p->total_packets = 0;
	p->missed_packets = 0;
	p->error_packets = 0;
	p->invalid_packets = 0;

	// Reset temporary buffer
	p->temp_buff_len = 0;

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


