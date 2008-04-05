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

#include "input_docsis.h"
#include "match_docsis.h" // For docsis header definition

#include "ptype_string.h"
#include "ptype_bool.h"
#include "ptype_uint32.h"


/// We use a bigger buffer size of the demux interface. This way we can cope with some burst.
#define DEMUX_BUFFER_SIZE 2097152 // 2Megs

int match_ethernet_id, match_docsis_id, match_atm_id;

struct input_mode *mode_normal, *mode_scan;
struct ptype *p_eurodocsis, *p_frequency, *p_modulation, *p_adapter, *p_frontend, *p_outlayer, *p_startfreq, *p_frontend_reinit, *p_tuning_timeout;

struct input_functions *ifcs;

/// Register input_docsis
int input_register_docsis(struct input_reg *r, struct input_functions *i_funcs) {


	r->init = input_init_docsis;
	r->open = input_open_docsis;
	r->getcaps = input_getcaps_docsis;
	r->read = input_read_docsis;
	r->close = input_close_docsis;
	r->cleanup = input_cleanup_docsis;
	r->unregister = input_unregister_docsis;

	ifcs = i_funcs;

	match_ethernet_id = (*i_funcs->match_register) ("ethernet");
	match_atm_id = (*i_funcs->match_register) ("atm");
	match_docsis_id = (*i_funcs->match_register) ("docsis");

	mode_normal = (*i_funcs->register_mode) (r->type, "normal", "Tune to a given frequency");
	mode_scan = (*i_funcs->register_mode) (r->type, "scan", "Scan for possible internet frequency");

	if (!mode_normal || !mode_scan)
		return POM_ERR;

	p_eurodocsis = (*i_funcs->ptype_alloc) ("bool", NULL);
	p_frequency = (*i_funcs->ptype_alloc) ("uint32", "Hz");
	p_modulation = (*i_funcs->ptype_alloc) ("string", NULL);
	p_adapter = (*i_funcs->ptype_alloc) ("uint16", NULL);
	p_frontend = (*i_funcs->ptype_alloc) ("uint16", NULL);
	p_outlayer = (*i_funcs->ptype_alloc) ("string", NULL);
	p_startfreq = (*i_funcs->ptype_alloc) ("uint32", "Hz");
	p_frontend_reinit = (*i_funcs->ptype_alloc) ("bool", NULL);
	p_tuning_timeout = (*i_funcs->ptype_alloc) ("uint32", "seconds");
	
	if (!p_eurodocsis || !p_frequency || !p_modulation || !p_adapter || !p_frontend || !p_outlayer || !p_startfreq || !p_frontend_reinit || !p_tuning_timeout) {
		input_unregister_docsis(r);
		return POM_ERR;
	}
	
	(*i_funcs->register_param) (mode_normal, "eurodocsis", "yes", p_eurodocsis, "Use EuroDOCSIS specification instead of normal DOCSIS specification");
	(*i_funcs->register_param) (mode_normal, "frequency", "440000000", p_frequency, "Frequency of the DOCSIS stream in Hz");
	(*i_funcs->register_param) (mode_normal, "modulation", "QAM256", p_modulation, "Modulation of the DOCSIS stream");
	(*i_funcs->register_param) (mode_normal, "adapter", "0", p_adapter, "ID of the DVB adapter to use");
	(*i_funcs->register_param) (mode_normal, "frontend", "0", p_frontend, "ID of the DVB frontend to use for the specified adapter");
	(*i_funcs->register_param) (mode_normal, "tuning_timeout", "3", p_tuning_timeout, "Timeout to wait until giving up when waiting for a lock");
	(*i_funcs->register_param) (mode_normal, "outlayer", "ethernet", p_outlayer, "Type of the output layer wanted");

	(*i_funcs->register_param) (mode_scan, "eurodocsis", "yes", p_eurodocsis, "Use EuroDOCSIS specification instead of normal DOCSIS specification");
	(*i_funcs->register_param) (mode_scan, "startfreq", "0", p_startfreq, "Starting frequency in Hz. Will use the default of the specification if 0");
	(*i_funcs->register_param) (mode_scan, "modulation", "QAM256", p_modulation, "Modulation of the DOCSIS stream");
	(*i_funcs->register_param) (mode_scan, "adapter", "0", p_adapter, "ID of the DVB adapter to use");
	(*i_funcs->register_param) (mode_scan, "frontend", "0", p_frontend, "ID of the DVB frontend to use for the specified adapter");
	(*i_funcs->register_param) (mode_scan, "frontend_reinit", "no", p_frontend_reinit, "Set to yes if the frontend needs to be closed and reopened between each scan");
	(*i_funcs->register_param) (mode_scan, "tuning_timeout", "3", p_tuning_timeout, "Timeout to wait until giving up when waiting for a lock");
	(*i_funcs->register_param) (mode_scan, "outlayer", "ethernet", p_outlayer, "Type of the output layer wanted");



	return POM_OK;
}

/** Always returns POM_OK. */
int input_init_docsis(struct input *i) {

	i->input_priv = malloc(sizeof(struct input_priv_docsis));
	bzero(i->input_priv, sizeof(struct input_priv_docsis));

	struct input_priv_docsis *p = i->input_priv;
	p->temp_buff = malloc(TEMP_BUFF_LEN);
	memset(p->temp_buff, 0xff, TEMP_BUFF_LEN);
	//(*ifcs->pom_log) (POM_LOG_TSHOOT "Temp buff is 0x%X-0x%X\r\n", (unsigned) p->temp_buff, (unsigned) p->temp_buff + TEMP_BUFF_LEN);

	return POM_OK;

}

/** Always returns POM_OK */
int input_cleanup_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	free(p->temp_buff);
	free(i->input_priv);

	return POM_OK;

}

int input_unregister_docsis(struct input_reg *r) {

	(*ifcs->ptype_cleanup) (p_eurodocsis);
	(*ifcs->ptype_cleanup) (p_frequency);
	(*ifcs->ptype_cleanup) (p_modulation);
	(*ifcs->ptype_cleanup) (p_adapter);
	(*ifcs->ptype_cleanup) (p_frontend);
	(*ifcs->ptype_cleanup) (p_outlayer);
	(*ifcs->ptype_cleanup) (p_startfreq);
	(*ifcs->ptype_cleanup) (p_frontend_reinit);
	(*ifcs->ptype_cleanup) (p_tuning_timeout);

	return POM_OK;
}

/**
 * If a frequency is not specified, it will scan for a tuneable freq.
 * Returns POM_ERR on failure or a file descriptor useable with select().
 **/
int input_open_docsis(struct input *i) {

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
		(*ifcs->pom_log) (POM_LOG_ERR "Invalid output layer :%s\r\n", PTYPE_STRING_GETVAL(p_outlayer));
		goto err;
	}


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
		(*ifcs->pom_log) (POM_LOG_ERR "Invalid modulation. Valid modulation are QAM64 or QAM256\r\n");
		goto err;
	}	
	
	// Open the frontend
	char adapter[NAME_MAX];
	bzero(adapter, NAME_MAX);
	strcpy(adapter, "/dev/dvb/adapter");
	(*ifcs->ptype_snprintf) (p_adapter, adapter + strlen(adapter), NAME_MAX - strlen(adapter));

	char frontend[NAME_MAX];
	strcpy(frontend, adapter);
	strcat(frontend, "/frontend");
	(*ifcs->ptype_snprintf) (p_frontend, frontend + strlen(frontend), NAME_MAX - strlen(frontend));

	p->frontend_fd = open(frontend, O_RDWR);
	if (p->frontend_fd == -1) {
		(*ifcs->pom_log) (POM_LOG_ERR "Unable to open frontend %s\r\n", frontend);
		goto err;
	}

	// Check if we are really using a DVB-C device
	
	struct dvb_frontend_info info;
	if (ioctl(p->frontend_fd, FE_GET_INFO, &info) != 0) {
		(*ifcs->pom_log) (POM_LOG_ERR "Unable to get frontend type\r\n");
		goto err;
	}

	if (info.type != FE_QAM) {
		(*ifcs->pom_log) (POM_LOG_ERR "Error, device %s is not a DVB-C device\r\n", frontend);
		goto err;
	}

	// Open the demux
	char demux[NAME_MAX];
	strcpy(demux, adapter);
	strcat(demux, "/demux0");

	p->demux_fd = open(demux, O_RDWR);
	if (p->demux_fd == -1) {
		(*ifcs->pom_log) ("Unable to open demux\r\n");
		goto err;
	}

	// Let's use a larger buffer
	if (ioctl(p->demux_fd, DMX_SET_BUFFER_SIZE, (unsigned long) DEMUX_BUFFER_SIZE) != 0) {
		char errbuff[256];
		strerror_r(errno, errbuff, 256);
		(*ifcs->pom_log) (POM_LOG_WARN "Unable to set the buffer size on the demux : %s\r\n", errbuff);
	}

	// Let's filter on the DOCSIS PID
	bzero(&filter, sizeof(struct dmx_pes_filter_params));	
	filter.pid = DOCSIS_PID;
	filter.input = DMX_IN_FRONTEND;
	filter.output = DMX_OUT_TS_TAP;
	filter.pes_type = DMX_PES_OTHER;
	filter.flags = DMX_IMMEDIATE_START;

	if (ioctl(p->demux_fd, DMX_SET_PES_FILTER, &filter) != 0) {
		(*ifcs->pom_log) (POM_LOG_ERR "Unable to set demuxer\r\n");
		goto err;
	}

	// Let's open the dvr device

	char dvr[NAME_MAX];
	strcpy(dvr, adapter);
	strcat(dvr, "/dvr0");

	p->dvr_fd = open(dvr, O_RDONLY);
	if (p->dvr_fd == -1) {
		(*ifcs->pom_log) (POM_LOG_ERR "Unable to open dvr interface\r\n");
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
			(*ifcs->pom_log) (POM_LOG_ERR "Error while tuning to the right freq\r\n");
			goto err;
		}
		if (input_docsis_check_downstream(i) == POM_ERR) {
			(*ifcs->pom_log) ("Error, no DOCSIS SYNC message received within timeout\r\n");
			goto err;
		}

	} else if (i->mode == mode_scan) { // No frequency supplied. Scanning for downstream


		unsigned int start = PTYPE_UINT32_GETVAL(p_startfreq);

		unsigned int end, step;
		int j;
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
			start = 91000000;
			end = 857000000;
			step = 1000000;
		}


		unsigned int need_reinit = PTYPE_BOOL_GETVAL(p_frontend_reinit);


		(*ifcs->pom_log)  ("Starting a scan from %uMhz to %uMhz\r\n", start / 1000000, end / 1000000);
		for (j = start; j <= end; j += step) {

			(*ifcs->pom_log) ("Tuning to %u Mhz ...\r\n", j / 1000000);

			int res = input_docsis_tune(i, j, symbolRate, modulation);
			if (res == POM_ERR)
				goto err;
			else if (res == 0) {
				if (need_reinit) {
					// Let's close and reopen the frontend to reinit it
					(*ifcs->pom_log) ("Reinitializing frontend ...\r\n");
					close(p->frontend_fd);
					sleep(10); // Yes, stupid frontends need to be closed to lock again or result is arbitrary
					p->frontend_fd = open(frontend, O_RDWR);
					if (p->frontend_fd == -1) {
						(*ifcs->pom_log) (POM_LOG_ERR "Error while reopening frontend\r\n");
						goto err;
					}
				}
				continue;
			}

			tuned = 1;

			(*ifcs->pom_log) ("Frequency tunned. Looking up for SYNC messages ...\r\n");

			if (input_docsis_check_downstream(i) == POM_ERR)
				continue;

			(*ifcs->pom_log) ("Downstream acquired !\r\n");
			(*ifcs->pom_log) ("Frequency : %f Mhz, Symbol rate : %u Sym/s, QAM : ", (double) j / 1000000.0, symbolRate);
			if (modulation == QAM_64)
				(*ifcs->pom_log) ("QAM64");
			else if(modulation == QAM_256)
				(*ifcs->pom_log) ("QAM256");
			(*ifcs->pom_log) ("\r\n");

			PTYPE_UINT32_SETVAL(p_frequency, j);

			i->mode = mode_normal;

			break;

		}

		if (j > end) {
			(*ifcs->pom_log) (POM_LOG_WARN "No DOCSIS stream found\r\n");
			goto err;
		}
	} else {
		(*ifcs->pom_log) (POM_LOG_ERR "Invalid input mode\r\n");
		goto err;
	}

	if (!tuned) {
		(*ifcs->pom_log) (POM_LOG_ERR "Failed to open docsis input\r\n");
		goto err;
	}

	(*ifcs->pom_log) ("Docsis stream opened successfullly\r\n");
	
	return p->dvr_fd;

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

int input_docsis_check_downstream(struct input *i) {

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
			(*ifcs->pom_log) (POM_LOG_ERR "Error select() : %s\r\n", errbuff);
			break;
		} else if (res == 0) {
			(*ifcs->pom_log) (POM_LOG_ERR "Timeout while waiting for data\r\n");
			break;
		}

		res = input_docsis_read_mpeg_frame(buffer, p);

		switch (res) {
			case -2:
				(*ifcs->pom_log) (POM_LOG_ERR "Error while reading MPEG stream\r\n");
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
		
		count++;

		if (count >= 10)
			return POM_OK;
		
	} 

	(*ifcs->pom_log) (POM_LOG_ERR "Did not receive SYNC message within timeout\r\n");
	return POM_ERR;
}

/**
 * This function will try to obtain a lock for tune_timeout seconds.
 * Returns 0 if not tuned in, 1 on success and -1 on fatal error.
 **/
int input_docsis_tune(struct input *i, uint32_t frequency, uint32_t symbolRate, fe_modulation_t modulation) {
	
	fe_status_t status;
	struct dvb_frontend_parameters frp;
	struct dvb_frontend_event event;


	struct pollfd pfd[1];

	struct input_priv_docsis *p = i->input_priv;


	bzero(&frp, sizeof(struct dvb_frontend_parameters));
	frp.frequency = frequency;
	frp.inversion = INVERSION_AUTO; // DOCSIS explicitly prohibit inversion but we keep AUTO to play it safe
	frp.u.qam.symbol_rate = symbolRate;
	frp.u.qam.fec_inner = FEC_AUTO;
	frp.u.qam.modulation = modulation;

	// Let's do some tuning

	if (ioctl(p->frontend_fd, FE_SET_FRONTEND, &frp) < 0){
		(*ifcs->pom_log) (POM_LOG_ERR "Error while setting tuning parameters\r\n");
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
					(*ifcs->pom_log) (POM_LOG_WARN "IOCTL failed while getting event of DOCSIS input\r\n");
					continue;
				}
				if (ioctl(p->frontend_fd, FE_READ_STATUS, &status)) {
					(*ifcs->pom_log) (POM_LOG_WARN "IOCTL failed while getting status of DOCSIS input\r\n");
					return -1;
				}
				
				if (status & FE_TIMEDOUT) {
					(*ifcs->pom_log) (POM_LOG_WARN "Timeout while tuning\r\n");
					return 0;
				}
				if (status & FE_REINIT) {
					(*ifcs->pom_log) (POM_LOG_WARN "Frontend was reinit\r\n");
					return 0;
				}
				
				if (status)
					(*ifcs->pom_log) (POM_LOG_DEBUG "Status : " );

				if (status & FE_HAS_SIGNAL)
					(*ifcs->pom_log) (POM_LOG_DEBUG "SIGNAL ");
				if (status & FE_HAS_CARRIER)
					(*ifcs->pom_log) (POM_LOG_DEBUG "CARRIER ");
				if (status & FE_HAS_VITERBI)
					(*ifcs->pom_log) (POM_LOG_DEBUG "VITERBI ");
				if (status & FE_HAS_SYNC)
					(*ifcs->pom_log) (POM_LOG_DEBUG "VSYNC ");
				if (status & FE_HAS_LOCK) {
					(*ifcs->pom_log) (POM_LOG_DEBUG "LOCK ");
					(*ifcs->pom_log) (POM_LOG_DEBUG "\r\n");
					return 1;
				}
				if (status)
					(*ifcs->pom_log) (POM_LOG_DEBUG "\r\n");


			} 
		} 
		gettimeofday(&now, NULL);
	}

	(*ifcs->pom_log) ("Lock not aquired\r\n");

	return 0;

}

/**
 * Fill buff with an MPEG packet of MPEG_TS_LEN bytes and check it's validity.
 * Returns 0 on success, 1 if PUSI is set, -1 if it's and invalid packet, -2 if there was an error while reading.
 */

int input_docsis_read_mpeg_frame(unsigned char *buff, struct input_priv_docsis *p) {
	

		// Fill the mpeg buffer
		size_t len = 0, r = 0;

		do {
			r = read(p->dvr_fd, buff + len, MPEG_TS_LEN - len);
			if (r <= 0 ) {
				(*ifcs->pom_log) (POM_LOG_ERR "Error while reading dvr\r\n");
				return -2;
			}
			len += r;
		} while (len < MPEG_TS_LEN);

		p->total_packets++;
		// Let's see if we should care about that packet
		
		// Check sync byte
		if (buff[0] != 0x47) {
			(*ifcs->pom_log) (POM_LOG_ERR "Error, stream out of sync ! Abording !\r\n");
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
 * Returns POM_OK or POM_ERR in case of fatal error.
 **/

int input_read_docsis(struct input *i, struct frame *f) {

	struct input_priv_docsis *p = i->input_priv;

	f->first_layer = p->output_layer;
	gettimeofday(&f->tv, NULL);

	unsigned int packet_pos = 0;
	unsigned char mpeg_buff[MPEG_TS_LEN];
	bzero(mpeg_buff, MPEG_TS_LEN);

	int dlen = 0; // len of the docsis MAC frame including headers

	// Copy leftover into current buffer
	if (p->temp_buff_len > 0) {

		int pos = 0;

		// Skip stuff bytes
		while (pos < p->temp_buff_len && p->temp_buff[pos] == 0xff)
			pos++;

		//(*ifcs->pom_log) (POM_LOG_TSHOOT "Copying1 %u bytes into 0x%X-0x%X\r\n", p->temp_buff_len - pos, (unsigned) f->buff,  (unsigned) f->buff + p->temp_buff_len - pos);
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
				//(*ifcs->pom_log) (POM_LOG_TSHOOT "Invalid packet. discarding.\r\n");
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
			//(*ifcs->pom_log) (POM_LOG_TSHOOT "buffer overflow2i\r\n");
			packet_pos = 0;
			dlen = 0;
		}

		int res = input_docsis_read_mpeg_frame(mpeg_buff, p);

		if (res == -2) // Error while reading
			return POM_ERR;


		// Check if we missed some packets. If so, fill the gap with 0xff
		p->last_seq = (p->last_seq + 1) & 0xF;
		while (p->last_seq != (mpeg_buff[3] & 0xF)) {
			p->last_seq = (p->last_seq + 1) & 0xF;
			p->missed_packets++;
			p->total_packets++;
			//(*ifcs->pom_log) (POM_LOG_TSHOOT "Filling1 %u bytes with 0xff at 0x%X-0x%X\r\n", MPEG_TS_LEN - 4,(unsigned) (f->buff + packet_pos), (unsigned) f->buff + packet_pos + MPEG_TS_LEN - 4);
			memset(f->buff + packet_pos, 0xff, MPEG_TS_LEN - 4); // Fill buffer with stuff byte
			packet_pos += MPEG_TS_LEN - 4;

			if (packet_pos + MPEG_TS_LEN - 4 >= f->bufflen) {
				//  buffer overflow. Let's discard the whole thing
				//(*ifcs->pom_log) (POM_LOG_TSHOOT "Buffer overflow\r\n");
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
				//(*ifcs->pom_log) (POM_LOG_TSHOOT "Filling2 %u bytes with 0xff at 0x%X-0x%X\r\n", MPEG_TS_LEN - 4,(unsigned) (f->buff + packet_pos), (unsigned) f->buff + packet_pos + MPEG_TS_LEN - 4);
				memset(f->buff + packet_pos, 0xff, MPEG_TS_LEN - 4); // Fill buffer with stuff byte
				packet_pos += MPEG_TS_LEN - 4;
				continue;

			case 0: // Packet is valid and does not contain the start of a PDU
				//(*ifcs->pom_log) (POM_LOG_TSHOOT "Copying2 %u bytes into 0x%X-0x%X\r\n", MPEG_TS_LEN - 4, (unsigned) f->buff + packet_pos, (unsigned) f->buff + packet_pos + MPEG_TS_LEN - 4);
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
						//(*ifcs->pom_log) (POM_LOG_TSHOOT "cruft left\r\n");
						packet_pos = 0;
					}

					// Skip possible stuff byte
					for (new_start = mpeg_buff[4] + 5; new_start < MPEG_TS_LEN && mpeg_buff[new_start + 5] == 0xff; new_start++);

					//(*ifcs->pom_log) (POM_LOG_TSHOOT "Copying3 %u bytes into 0x%X-0x%X\r\n", MPEG_TS_LEN - new_start, (unsigned) f->buff + packet_pos, (unsigned) f->buff + packet_pos + MPEG_TS_LEN - new_start);
					memcpy(f->buff + packet_pos, mpeg_buff + new_start, MPEG_TS_LEN - new_start);
					packet_pos = MPEG_TS_LEN - new_start;

					continue;
				}
				

				// Se we got part of the last and new PDU here
				// Let's copy everything, we'll later what is part of new PDU
				
				// last packet
				//(*ifcs->pom_log) (POM_LOG_TSHOOT "Copying5 %u bytes into 0x%X-0x%X\r\n", MPEG_TS_LEN - 5, (unsigned) f->buff + packet_pos, (unsigned) f->buff + packet_pos + MPEG_TS_LEN - 5);
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
		//(*ifcs->pom_log) (POM_LOG_TSHOOT "Copying7 %u bytes into 0x%X-0x%X\r\n", packet_pos - dlen, (unsigned) p->temp_buff + p->temp_buff_len, (unsigned) p->temp_buff + p->temp_buff_len + packet_pos - dlen);
		memcpy(p->temp_buff, f->buff + dlen, packet_pos - dlen);
		p->temp_buff_len = packet_pos - dlen;
	} 


	if (p->output_layer == match_ethernet_id || p->output_layer == match_atm_id) {

		if (p->output_layer == match_ethernet_id) {
			if (dhdr->fc_type != FC_TYPE_PKT_MAC) {
				//(*ifcs->pom_log) (POM_LOG_TSHOT "output type is ethernet and fc_type doesn't match. ignoring\r\n");
				f->len = 0;
				return POM_OK;
			}
			if (dlen < 64) { // Minimum ethernet len
				f->len = 0;
				return POM_OK;
			}

			// We don't need the last 4 bytes containing the ethernet checksum
			dlen -= 4;
		}

		if (p->output_layer == match_atm_id) {
			if (dhdr->fc_type != FC_TYPE_ATM) {
				//(*ifcs->pom_log) (POM_LOG_TSHOOT "output type is atm and fc_type doesn't match. ignoring\r\n");	
				f->len = 0;
				return POM_OK;
			}
			if (dlen % 53) // dlen is not a multiple of atm cell
				f->len = 0;
				return POM_OK;
		}

		dlen -= sizeof(struct docsis_hdr);
		unsigned int new_start = sizeof(struct docsis_hdr);
		
		// fc_parm is len of ehdr if ehdr_on == 1
		if (dhdr->ehdr_on) {
			new_start += dhdr->fc_parm;
			dlen -= new_start;
		
		}

		//(*ifcs->pom_log) (POM_LOG_TSHOOT "calculated dlen is %u\r\n", dlen);

		memmove(f->buff, f->buff + new_start, dlen);




	}


	//(*ifcs->pom_log) (POM_LOG_TSHOOT "outlayer : %u\r\n", p->output_layer);
	//(*ifcs->pom_log) (POM_LOG_TSHOOT "RETURNING packet of %u\r\n", dlen);

	f->len = dlen;
	return POM_OK;





}

/**
 * Returns POM_OK on success and POM_ERR on failure.
 **/
int input_close_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	if (!p)
		return POM_ERR;
	
	close(p->frontend_fd);
	close(p->demux_fd);
	close(p->dvr_fd);

	(*ifcs->pom_log) ("0x%02lx; DOCSIS : Total MPEG packet read %lu, missed %lu (%.1f%%), erroneous %lu (%.1f%%), invalid %lu (%.1f%%), total errors %lu (%.1f%%)\r\n", \
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




	return POM_OK;

}

int input_getcaps_docsis(struct input *i, struct input_caps *ic) {

	ic->snaplen = 1800; /// Must be at least that high for internal processing
	ic->is_live = 1;
	ic->buff_align_offset = 0;

	return POM_OK;

}


