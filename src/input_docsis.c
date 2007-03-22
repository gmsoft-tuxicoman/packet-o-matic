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

#define DEMUX_BUFFER_SIZE 2097152 // 2Megs

#define PARAMS_NUM 9

char *input_docsis_params[PARAMS_NUM][3] = {
	{ "eurodocsis", "1", "DOCSIS specification to use. 1 for eurodocsis else 0" },
	{ "frequency", "0", "frequency to scan to in Hz. if 0, a scan will be performed" },
	{ "modulation", "QAM256", "the modulation to use. either QAM64 or QAM256" },
	{ "adapter", "0", "DVB adapter to use" },
	{ "frontend", "0", "DVB frontend to use" },
	{ "outlayer", "ethernet", "choose output layer : ethernet, atm or docsis" },
	{ "scanstart", "0", "start docsis scan at this frequency (in Hz)" },
	{ "frontend_reinit", "0", "set to 1 if frontend needs to be closed and reopened between each scan" },
	{ "tuning_timeout", "10", "seconds we'll wait for a lock" },
};

int match_ethernet_id, match_docsis_id, match_atm_id;

int input_register_docsis(struct input_reg *r, struct input_functions *i_funcs) {


	copy_params(r->params_name, input_docsis_params, 0, PARAMS_NUM);
	copy_params(r->params_help, input_docsis_params, 2, PARAMS_NUM);


	r->init = input_init_docsis;
	r->open = input_open_docsis;
	r->get_first_layer = input_get_first_layer_docsis;
	r->read = input_read_docsis;
	r->close = input_close_docsis;
	r->cleanup = input_cleanup_docsis;

	match_ethernet_id = (*i_funcs->match_register) ("ethernet");
	match_atm_id = (*i_funcs->match_register) ("atm");
	match_docsis_id = (*i_funcs->match_register) ("docsis");

	return 1;
}


int input_init_docsis(struct input *i) {

	i->input_priv = malloc(sizeof(struct input_priv_docsis));
	bzero(i->input_priv, sizeof(struct input_priv_docsis));

	struct input_priv_docsis *p = i->input_priv;
	p->temp_buff = malloc(TEMP_BUFF_LEN);
	ndprint("Temp buff is 0x%X-0x%X\n", (unsigned) p->temp_buff, (unsigned) p->temp_buff + TEMP_BUFF_LEN);

	copy_params(i->params_value, input_docsis_params, 1, PARAMS_NUM);


	return 1;

}

int input_cleanup_docsis(struct input *i) {

	clean_params(i->params_value, PARAMS_NUM);

	struct input_priv_docsis *p = i->input_priv;
	free(p->temp_buff);
	free(i->input_priv);

	return 1;

};

int input_open_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	struct dmx_pes_filter_params filter;


	// Select the output type
	if (!strcmp(i->params_value[5], "ethernet")) {
		p->output_layer = match_ethernet_id;
	} else if (!strcmp(i->params_value[5], "atm")) {
		p->output_layer = match_atm_id;
	} else if (!strcmp(i->params_value[5], "docsis")) {
		p->output_layer = match_docsis_id;
	} else {
		dprint("Invalid output layer :%s\n", i->params_value[5]);
		return -1;
	}


	// Parse eurodocsis and frequency
	int eurodocsis, frequency;
	sscanf(i->params_value[0], "%u", &eurodocsis);
	sscanf(i->params_value[1], "%u", &frequency);

	fe_modulation_t modulation;
	if (!strcmp(i->params_value[2], "QAM64"))
		modulation = QAM_64;
	else if (!strcmp(i->params_value[2], "QAM256"))
		modulation = QAM_256;
	else {
		dprint("Invalid modulation. Valid modulation are QAM64 or QAM256\n");
		return -1;
	}	
	
	// Open the frontend
	char adapter[NAME_MAX];
	bzero(adapter, NAME_MAX);
	strcpy(adapter, "/dev/dvb/adapter");
	strcat(adapter, i->params_value[3]);

	char frontend[NAME_MAX];
	strcpy(frontend, adapter);
	strcat(frontend, "/frontend");
	strcat(frontend, i->params_value[4]);

	p->frontend_fd = open(frontend, O_RDWR);
	if (p->frontend_fd == -1) {
		dprint("Unable to open frontend\n");
		return -1;
	}

	// Check if we are really using a DVB-C device
	
	struct dvb_frontend_info info;
	if (ioctl(p->frontend_fd, FE_GET_INFO, &info) != 0) {
		dprint("Unable to get frontend type\n");
		return -1;
	}

	if (info.type != FE_QAM) {
		dprint("Error, device %s is not a DVB-C device\n", frontend);
		return -1;
	}

	// Open the demux
	char demux[NAME_MAX];
	strcpy(demux, adapter);
	strcat(demux, "/demux0");

	p->demux_fd = open(demux, O_RDWR);
	if (p->demux_fd == -1) {
		dprint("Unable to open demux\n");
		return -1;
	}

	// Let's use a larger buffer
	if (ioctl(p->demux_fd, DMX_SET_BUFFER_SIZE, (unsigned long) DEMUX_BUFFER_SIZE) != 0) {
		dprint("Unable to set the buffer size on the demux : %s\n", strerror(errno));
	}

	// Let's filter on the DOCSIS PID
	
	filter.pid = DOCSIS_PID;
	filter.input = DMX_IN_FRONTEND;
	filter.output = DMX_OUT_TS_TAP;
	filter.pes_type = DMX_PES_OTHER;
	filter.flags = DMX_IMMEDIATE_START;


	if (ioctl(p->demux_fd, DMX_SET_PES_FILTER, &filter) != 0) {
		dprint("Unable to set demuxer\n");
		return -1;
	}


	// Let's open the dvr device

	char dvr[NAME_MAX];
	strcpy(dvr, adapter);
	strcat(dvr, "/dvr0");

	p->dvr_fd = open(dvr, O_RDONLY);
	if (p->dvr_fd == -1) {
		dprint("Unable to open dvr\n");
		return -1;
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
	if (frequency != 0) {
		int try;
		for (try = 0; try < 3; try++) {
			tuned = input_docsis_tune(i, frequency, symbolRate, modulation);
			if (tuned == 1)
				break;
		}
		
		if (tuned != 1) {
			dprint("Error while tuning to the right freq.\n");
			return -1;
		}
		if (!input_docsis_check_downstream(i)) {
			dprint("Error, no DOCSIS SYNC message received within timeout\n");
			return -1;
		}

	} else  { // No frequency supplied. Scanning for downstream


		unsigned int start, end, step;
		int j;
		if (eurodocsis) {
			start = 112000000;
			end = 858000000;
			step = 1000000;

		} else {
			start = 91000000;
			end = 857000000;
			step = 1000000;
		}

		unsigned int scanstart;

		sscanf(i->params_value[6], "%u", &scanstart);
		if (scanstart > start && scanstart < end)
			start = scanstart;

		unsigned int need_reinit;
		sscanf(i->params_value[7], "%u", &need_reinit);


		dprint("No frequency specified. starting a scan from %uMhz to %uMhz\n", start / 1000000, end / 1000000);
		for (j = start; j <= end; j += step) {

			dprint("Tuning to %u Mz ...\n", j / 1000000);

			int res = input_docsis_tune(i, j, symbolRate, modulation);
			if (res == -1)
				return -1;
			else if (res == 0) {
				if (need_reinit) {
					// Let's close and reopen the frontend to reinit it
					dprint("Reinitializing frontend ...\n");
					close(p->frontend_fd);
					sleep(10); // Yes, stupid frontends need to be closed to lock again or result is arbitrary
					p->frontend_fd = open(frontend, O_RDWR);
					if (p->frontend_fd == -1) {
						dprint("Error while reopening frontend\n");
						return -1;
					}
				}
				continue;
			}

			tuned = 1;

			dprint("Frequency tunned. Looking up for SYNC messages ...\n");

			if (!input_docsis_check_downstream(i))
				continue;

			dprint("Downstream acquired !\n");
			dprint("Frequency : %f Mhz, Symbol rate : %u Sym/s, QAM : ", (double) j / 1000000.0, symbolRate);
			if (modulation == QAM_64)
				dprint("QAM64");
			else if(modulation == QAM_256)
				dprint("QAM256");
			dprint("\n");
			break;

		}
	}

	if (!tuned) {
		dprint("Failed to open docsis input\n");
		return -1;
	}

	dprint("Docsis stream opened successfullly\n");
	
	return p->dvr_fd;
}


int input_docsis_check_downstream(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;

	unsigned char buffer[MPEG_TS_LEN];
	int count = 0, len = 0, res;
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
			dprint("Error select() : %s\n", strerror(errno));
			break;
		} else if (res == 0) {
			dprint("Timeout while waiting for data\n");
			break;
		}
	
		len = 0;

		while (len < MPEG_TS_LEN) {
			res = read(p->dvr_fd, buffer + len, MPEG_TS_LEN - len);
			if (res <= 0) {
				dprint("Error while reading\n");
				return 0;
			}
			len += res;
		}

		// Let's see if we should care about that packet
		
		// Check sync byte
		if (buffer[0] != 0x47) {
			dprint("Error, stream out of sync ! Abording !\n");
			return -1;
		}
		
		// Check transport error indicator
		if (buffer[1] & 0x80)
			continue;
		
		// Check if payload unit start indicator is present and if it is valid
		if (buffer[1] & 0x40 && (buffer[4] > 183))
			continue;
		
		// Check the transport priority
		if (buffer[1] & 0x20)
			continue;

		// Check for the right PID, normaly the demux handle this
		if ( ((buffer[1] & 0x1F) != 0x1F) && (buffer[2] != 0xFE))
			continue;

		// Check the transport scrambling control
		if (buffer[3] & 0xC0)
			continue;

		// Check the adaptation field control
		if ((buffer[3] & 0x30) != 0x10)
			continue;


		// Checking if PUSI = 1 (SYNC message are not allowed to cross mpeg packets)
		if (!(buffer[1] & 0x40))
			continue;

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
			return 1;
		
	} 

	dprint("Did not receive SYNC message within timeout\n");
	return 0;
}


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
		dprint("Error while setting tuning parameters\n");
		return -1;
	}


	pfd[0].fd = p->frontend_fd;
	pfd[0].events = POLLIN;

	int try = 0;

	int tune_timeout;
	sscanf(i->params_value[8], "%u", &tune_timeout);

	while (try < tune_timeout) {
		if (poll(pfd, 1, 1000)){
			if (pfd[0].revents & POLLIN) {
				if (ioctl(p->frontend_fd, FE_GET_EVENT, &event)) {
					dprint("IOCTL failed\n");
					return -1;
				}
				if (ioctl(p->frontend_fd, FE_READ_STATUS, &status)) {
					dprint("IOCTL failed\n");
					return -1;
				}
				
				if (status & FE_TIMEDOUT) {
					dprint("Timeout while tuning\n");
					return 0;
				}
				if (status & FE_REINIT) {
					dprint("Frontend was reinit\n");
					return 0;
				}
				
				if (status)
					dprint("Status : " );

				if (status & FE_HAS_SIGNAL)
					dprint("SIGNAL ");
				if (status & FE_HAS_CARRIER)
					dprint("CARRIER ");
				if (status & FE_HAS_VITERBI)
					dprint("VITERBI ");
				if (status & FE_HAS_SYNC)
					dprint("VSYNC ");
				if (status & FE_HAS_LOCK) {
					dprint("LOCK ");
					dprint("\n");
					return 1;
				} else if (status) {
					dprint("\n");
					break;
				}
				if (status)
					dprint("\n");


			} else
				try++;
		} else
			try++;
	};

	dprint("Lock not aquired\n");

	return 0;

}

int input_get_first_layer_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	return p->output_layer;

}


/*
 * buff : mpeg_buffer to fill of size MPEG_TS_LEN
 *
 * returns 0 on success, 1 if pusi is set, -1 if it's and invalid packet, -2 if there was an error
 *
 */

int input_docsis_read_mpeg_frame(unsigned char *buff, struct input_priv_docsis *p) {
	

		// Fill the mpeg buffer
		size_t len = 0, r = 0;

		do {
			r = read(p->dvr_fd, buff + len, MPEG_TS_LEN - len);
			if (r <= 0 ) {
				dprint("Error while reading dvr\n");
				return -2;
			}
			len += r;
		} while (len < MPEG_TS_LEN);

		p->total_packets++;
		// Let's see if we should care about that packet
		
		// Check sync byte
		if (buff[0] != 0x47) {
			dprint("Error, stream out of sync ! Abording !\n");
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

int input_read_docsis(struct input *i, unsigned char *buffer, unsigned int bufflen) {

	struct input_priv_docsis *p = i->input_priv;

	unsigned int packet_pos = 0;
	unsigned char mpeg_buff[MPEG_TS_LEN];
	bzero(mpeg_buff, MPEG_TS_LEN);

	int dlen = 0; // len of the docsis MAC frame including headers
	int new_start = 0;

	// Copy leftover into current buffer
	if (p->temp_buff_len > 0) {

		int pos = 0;

		// Skip stuff bytes
		while (pos < p->temp_buff_len && p->temp_buff[pos] == 0xff)
			pos++;


		ndprint("Copying1 %u bytes into 0x%X-0x%X\n", p->temp_buff_len - pos, (unsigned) buffer,  (unsigned) buffer + p->temp_buff_len - pos);
		memcpy(buffer, p->temp_buff + pos, p->temp_buff_len - pos);
		packet_pos = p->temp_buff_len - pos;

		// We don't need anything from the temp buffer now
		p->temp_buff_len = 0;
	
	}

	
	struct docsis_hdr *dhdr = (struct docsis_hdr*) buffer;

	// This only works because we can only capture downstream frames
	// Upstream can have REQ frame in which then len field correspond to service id
	while (1) {
		
		if (packet_pos > sizeof(struct docsis_hdr)) {

			dlen = ntohs(dhdr->len) + sizeof(struct docsis_hdr);

			
			if (dlen < sizeof(struct docsis_hdr) || dlen > bufflen) {
				// Invalid packet, let's discard the whole thing
				ndprint("Invalid packet. discarding.\n");
				packet_pos = 0;
				dlen = 0;
			}

			// We've got a full packet
			if (dlen <= packet_pos)
				break;

		}

		int res = input_docsis_read_mpeg_frame(mpeg_buff, p);

		if (packet_pos == 0)
			dlen = ntohs(dhdr->len) + sizeof(struct docsis_hdr);

		if (res == -2) // Error while reading
			return -1;

		p->last_seq = (p->last_seq + 1) & 0xF;
		while (p->last_seq != (mpeg_buff[3] & 0xF)) {
			p->last_seq = (p->last_seq + 1) & 0xF;
			p->missed_packets++;
			if (packet_pos + MPEG_TS_LEN - 4 >= bufflen) {
				//  buffer overflow. Let's discard the whole thing
				ndprint("Buffer overflow\n");
				packet_pos = 0;
				dlen = 0;
				break;
			}
			ndprint("Filling1 %u bytes with 0xff at 0x%X-0x%X\n", MPEG_TS_LEN - 4,(unsigned) (buffer + packet_pos), (unsigned) buffer + packet_pos + MPEG_TS_LEN - 4);
			memset(buffer + packet_pos, 0xff, MPEG_TS_LEN - 4); // Fill buffer with stuff byte
			packet_pos += MPEG_TS_LEN - 4;
		}

		//  buffer overflow. Let's discard the whole thing
		if (packet_pos + MPEG_TS_LEN - 4 >= bufflen) {
			ndprint("buffer overflow2\n");
			packet_pos = 0;
			dlen = 0;
		}


		switch (res) {
			case -1: // Invalid MPEG packet
				ndprint("Filling2 %u bytes with 0xff at 0x%X-0x%X\n", MPEG_TS_LEN - 4,(unsigned) (buffer + packet_pos), (unsigned) buffer + packet_pos + MPEG_TS_LEN - 4);
				memset(buffer + packet_pos, 0xff, MPEG_TS_LEN - 4); // Fill buffer with stuff byte
				packet_pos += MPEG_TS_LEN - 4;
				continue;

			case 0: // Packet is valid and does not contain the start of a PDU
				ndprint("Copying2 %u bytes into 0x%X-0x%X\n", MPEG_TS_LEN - 4, (unsigned) buffer + packet_pos, (unsigned) buffer + packet_pos + MPEG_TS_LEN - 4);
				memcpy(buffer + packet_pos, mpeg_buff + 4, MPEG_TS_LEN - 4);
				packet_pos += MPEG_TS_LEN - 4;
				continue;

			case 1:	// Packet is valid and contains the start of a PDU

				new_start = packet_pos + mpeg_buff[4];


				if (mpeg_buff[4] == 0) {
					ndprint("Start of new packet\n");
					// The begining of the MAC frame is at the start of the MPEG payload
					if (packet_pos > 0) {
						// We got some cruft left. Discard the current buffer
						ndprint("cruft left\n");
						packet_pos = 0;
					}

					ndprint("Copying3 %u bytes into 0x%X-0x%X\n", MPEG_TS_LEN - 5, (unsigned) buffer + packet_pos, (unsigned) buffer + packet_pos + MPEG_TS_LEN - 5);
					memcpy(buffer + packet_pos, mpeg_buff + 5, MPEG_TS_LEN - 5);
					packet_pos = MPEG_TS_LEN - 5;

					dlen = ntohs(dhdr->len) + sizeof(struct docsis_hdr);

					continue;
				}
				
				if (new_start < sizeof(struct docsis_hdr) || dlen > new_start) {
					// Either the given size can't contain even a header
					// Either the calulated size doesn't fit the gap
					// let's discard the previous frame then
					ndprint("discard previous frame\n");
					packet_pos = MPEG_TS_LEN - 5 - mpeg_buff[4];
					ndprint("Copying4 %u bytes into 0x%X-0x%X\n", packet_pos, (unsigned) buffer, (unsigned) buffer + packet_pos);
					memcpy(buffer, mpeg_buff + 5 + mpeg_buff[4], packet_pos);
					continue;
					
				}
				

				// Se we got part of the last and new PDU here
				// Let's split it up
				
				// last packet
				ndprint("Copying5 %u bytes into 0x%X-0x%X\n", mpeg_buff[4], (unsigned) buffer + packet_pos, (unsigned) buffer + packet_pos + mpeg_buff[4]);
				memcpy(buffer + packet_pos, mpeg_buff + 5, mpeg_buff[4]);
				packet_pos += mpeg_buff[4];

				ndprint("Copying6 %u bytes into 0x%X-0x%X\n", MPEG_TS_LEN - 5 - mpeg_buff[4], (unsigned) p->temp_buff, (unsigned) p->temp_buff + MPEG_TS_LEN - 5 - mpeg_buff[4]);
				memcpy(p->temp_buff, mpeg_buff + 5 + mpeg_buff[4], MPEG_TS_LEN - 5 - mpeg_buff[4]);
				p->temp_buff_len += MPEG_TS_LEN - 5 - mpeg_buff[4];

				continue;

			default: // Should not be reached
				return -1;

		}


	}
	// We have a full packet !

	if (dlen < packet_pos) { // Copy leftover if any
		ndprint("Copying7 %u bytes into 0x%X-0x%X\n", packet_pos - dlen, (unsigned) p->temp_buff + p->temp_buff_len, (unsigned) p->temp_buff + p->temp_buff_len + packet_pos - dlen);
		memcpy(p->temp_buff + p->temp_buff_len, buffer + dlen, packet_pos - dlen);
		p->temp_buff_len += packet_pos - dlen;
	} 


	if (p->output_layer == match_ethernet_id || p->output_layer == match_atm_id) {

		if (p->output_layer == match_ethernet_id) {
			if (dhdr->fc_type != FC_TYPE_PKT_MAC) {
				ndprint("output type is ethernet and fc_type doesn't match. ignoring\n");
				return 0;
			}
			if (dlen < 64) // Minimum ethernet len
				return 0;
		}

		if (p->output_layer == match_atm_id) {
			if (dhdr->fc_type != FC_TYPE_ATM) {
				ndprint("output type is atm and fc_type doesn't match. ignoring\n");	
				return 0;
			}
			if (dlen % 53) // dlen is not a multiple of atm cell
				return 0;
		}

		dlen -= sizeof(struct docsis_hdr);
		new_start = sizeof(struct docsis_hdr);
		
		// fc_parm is len of ehdr if ehdr_on == 1
		if (dhdr->ehdr_on) {
			new_start += dhdr->fc_parm;
			dlen -= new_start;
		
		}

		ndprint("calculated dlen is %u\n", dlen);

		memmove(buffer, buffer + new_start, dlen);




	}


	ndprint("outlayer : %u\n", p->output_layer);
	ndprint("RETURNING packet of %u\n", dlen);

	return dlen;





}

int input_close_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	if (!p)
		return 0;
	
	close(p->frontend_fd);
	close(p->demux_fd);
	close(p->dvr_fd);

	dprint("0x%02lx; DOCSIS : Total packet read %lu, missed %lu (%.1f%%),  erroneous %lu (%.1f%%), invalid %lu (%.1f%%), total errors %lu (%.1f%%)\n", \
		(unsigned long) i->input_priv, \
		p->total_packets, \
		p->missed_packets, \
		100.0 / (double) p->total_packets * (double) p->missed_packets, \
		p->error_packets, \
		100.0 / (double) p->total_packets * (double) p->error_packets, \
		p->invalid_packets, \
		100.0 / (double) p->total_packets * (double) p->invalid_packets, \
		p->missed_packets + p->error_packets + p->invalid_packets, \
		100.0 / (double) p->total_packets * (double) (p->missed_packets  + p->error_packets + p->invalid_packets));




	return 1;

}
