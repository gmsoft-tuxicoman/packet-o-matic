#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/poll.h>

#include <sys/select.h>

#include <linux/dvb/dmx.h>

#include <sys/ioctl.h>
#include <errno.h>

#include "input_docsis.h"

#define DEMUX_BUFFER_SIZE 2097152 // 2Megs

#define PARAMS_NUM 5

char *input_docsis_params[PARAMS_NUM][3] = {
	{ "eurodocsis", "1", "DOCSIS specification to use" },
	{ "frequency", "0", "frequency to scan to. if 0, a scan will be performed" },
	{ "modulation", "QAM256", "the modulation to use. either QAM64 or QAM256" },
	{ "adapter", "0", "DVB adapter to use" },
	{ "frontend", "0", "DVB frontend to use" },
};

int input_register_docsis(struct input_reg *r) {


	copy_params(r->params_name, input_docsis_params, 0, PARAMS_NUM);
	copy_params(r->params_help, input_docsis_params, 2, PARAMS_NUM);


	r->init = input_init_docsis;
	r->open = input_open_docsis;
	r->read = input_read_docsis;
	r->close = input_close_docsis;
	r->cleanup = input_cleanup_docsis;

	return 1;
}


int input_init_docsis(struct input *i) {

	i->input_priv = malloc(sizeof(struct input_priv_docsis));
	bzero(i->input_priv, sizeof(struct input_priv_docsis));

	copy_params(i->params_value, input_docsis_params, 1, PARAMS_NUM);

	return 1;

}

int input_cleanup_docsis(struct input *i) {

	clean_params(i->params_value, PARAMS_NUM);

	if (i->input_priv)
		free(i->input_priv);

	return 1;

};

int input_open_docsis(struct input *i) {

	struct dmx_pes_filter_params filter;

	struct input_priv_docsis *p = i->input_priv;

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
		return 0;
	}	
	
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
		return 0;
	}

	char demux[NAME_MAX];
	strcpy(demux, adapter);
	strcat(demux, "/demux0");

	p->demux_fd = open(demux, O_RDWR);
	if (p->demux_fd == -1) {
		dprint("Unable to open demux\n");
		return 0;
	}


	// Let's use a larger buffer

	if (ioctl(p->demux_fd, DMX_SET_BUFFER_SIZE, (unsigned long) DEMUX_BUFFER_SIZE) != 0) {
		dprint("Unable to set the buffer size on the demux : %s\n", strerror(errno));
	}


	// Yeah we got a lock. Let's filter on the DOCSIS PID
	
	filter.pid = DOCSIS_PID;
	filter.input = DMX_IN_FRONTEND;
	filter.output = DMX_OUT_TS_TAP;
	filter.pes_type = DMX_PES_OTHER;
	filter.flags = DMX_IMMEDIATE_START;


	if (ioctl(p->demux_fd, DMX_SET_PES_FILTER, &filter) != 0) {
		dprint("Unable to set demuxer\n");
		return 0;
	}


	// Let's open the dvr device

	char dvr[NAME_MAX];
	strcpy(dvr, adapter);
	strcat(dvr, "/dvr0");

	p->dvr_fd = open(dvr, O_RDONLY);
	if (p->dvr_fd == -1) {
		dprint("Unable to open dvr\n");
		return 0;
	}

	// Frequency and modulation supplied. Tuning to that
	if (frequency != -1) {
		unsigned int symboleRate;
		if (eurodocsis)
			symboleRate = 6952000;
		else if (modulation == QAM_64)
			symboleRate = 5056941;
		else // QAM_256
			symboleRate = 5360537;
		int try, tuned;
		for (try = 0; try < 3; try++) {
			tuned = input_docsis_tune(i, frequency, symboleRate, modulation);
			if (tuned == 1)
				break;
		}
		
		if (tuned != 1) {
			dprint("Error while tuning to the right freq.\n");
			return 0;
		}
		if (!input_docsis_check_downstream(i)) {
			dprint("Error, no DOCSIS SYNC message received within timeout\n");
			return 0;
		}

	} else  { // No frequency supplied. Scanning for downstream


		unsigned int start, end, step, symboleRate;
		int j;
		fe_modulation_t modulation;
		if (eurodocsis) {
			start = 112000000;
			end = 858000000;
			step = 1000000;
			// modulation = QAM_64;
			// symboleRate = 6952000;
			modulation = QAM_256;
			symboleRate = 6952000;

		} else {
			start = 91000000;
			end = 857000000;
			step = 1000000;
			modulation = QAM_64;
			symboleRate = 5056941;
			// modulation = QAM_256;
			// symboleRate = 5360537;
		}

		for (j = start; j <= end; j += step) {

			dprint("Tuning to %u Mz ...\n", j / 1000000);

			int res = input_docsis_tune(i, j, symboleRate, modulation);
			if (res == -1)
				return 0;
			else if (res == 0)
				continue;

			dprint("Frequency tunned. Looking up for SYNC messages ...\n");

			if (!input_docsis_check_downstream(i))
				continue;

			dprint("Downstream Aquired !\n");
			dprint("Frequency : %f Mhz, Symbole rate : %u Sym/s, QAM : ", (double) j / 1000000.0, symboleRate);
			if (modulation == QAM_64)
				dprint("QAM64");
			else if(modulation == QAM_256)
				dprint("QAM256");
			dprint("\n");
			break;

		}
	}

	dprint("Docsis stream opened successfullly\n");
	
	return 1;
}


int input_docsis_check_downstream(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;

	unsigned char buffer[MPEG_TS_LEN];
	int count = 0, len = 0, res;
	time_t sync_start = time(NULL);

	fd_set set;
	struct timeval tv = { 3 , 0 };
		

	while (time(NULL) - sync_start <= 2) {
		
		FD_ZERO(&set);
		FD_SET(p->dvr_fd, &set);
		
		res = select(p->dvr_fd + 1, &set, NULL, NULL, &tv);
		
		tv.tv_sec = 1;
		tv.tv_usec = 0;

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

	dprint("Did not received SYNC message within timeout\n");
	return 0;
}


int input_docsis_tune(struct input *i, uint32_t frequency, uint32_t symboleRate, fe_modulation_t modulation) {
	
	fe_status_t status;
	struct dvb_frontend_parameters frp;
	struct dvb_frontend_event event;


	struct pollfd pfd[1];

	struct input_priv_docsis *p = i->input_priv;

	frp.frequency = frequency;
	frp.inversion = INVERSION_OFF; // DOCSIS explicitly prohibit inversion
	frp.u.qam.symbol_rate = symboleRate;
	frp.u.qam.fec_inner = FEC_AUTO;
	frp.u.qam.modulation = modulation;

	// Let's do some tuning

	if (ioctl(p->frontend_fd, FE_SET_FRONTEND, &frp) < 0){
		dprint("Error while setting tuning parameters\n");
		return -1;
	}


	pfd[0].fd = p->frontend_fd;
	pfd[0].events = POLLIN;

	do {
		if (poll(pfd, 1, 3000)){
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

			}
		} else {
			break;
		}
	} while(1);

	dprint("Lock not aquired\n");

	return 0;

}

int input_read_docsis(struct input *i, unsigned char *buffer, unsigned int bufflen) {

	struct input_priv_docsis *p = i->input_priv;

	// Set to 1 if there are some mpeg packets lost for the current docsis packet
	unsigned int missing_parts = 0;
	unsigned int packet_pos = 0;
	unsigned char mpeg_buff[MPEG_TS_LEN];
	bzero(mpeg_buff, MPEG_TS_LEN);

	// Copy the leftover from last time
	if (p->temp_buff_pos > bufflen) {
		dprint("Please increase your read buffer (needed %u, given %u)\n", p->temp_buff_pos, bufflen);
		return 0;
	}

	memcpy(buffer, p->temp_buff, p->temp_buff_pos);

	packet_pos = p->temp_buff_pos;

	do {

		// Fill the mpeg buffer
		size_t len = 0, r = 0;

		do {
			r = read(p->dvr_fd, mpeg_buff, MPEG_TS_LEN);
			if (r <= 0 ) {
				dprint("Error while reading dvr\n");
				return -1;
			}
			len += r;
		} while (len < MPEG_TS_LEN);

		// Let's see if we should care about that packet
		
		// Check sync byte
		if (mpeg_buff[0] != 0x47) {
			dprint("Error, stream out of sync ! Abording !\n");
			return -1;
		}
		
		// Check transport error indicator
		if (mpeg_buff[1] & 0x80) {
			p->error_packets++;
			continue;
		}
		
		// Check if payload unit start indicator is present and if it is valid
		if (mpeg_buff[1] & 0x40 && (mpeg_buff[4] > 183)) {
			p->invalid_packets++;
			continue;
		}
		
		// Check the transport priority
		if (mpeg_buff[1] & 0x20) {
			p->invalid_packets++;
			continue;
		}

		// Check for the right PID, normaly the demux handle this
		if ( ((mpeg_buff[1] & 0x1F) != 0x1F) && (mpeg_buff[2] != 0xFE)) {
			p->invalid_packets++;
			continue;
		}

		// Check the transport scrambling control
		if (mpeg_buff[3] & 0xC0) {
			p->invalid_packets++;
			continue;
		}

		// Check the adaptation field control
		if ((mpeg_buff[3] & 0x30) != 0x10) {
			p->invalid_packets++;
			continue;
		}
		
		// Enough checking. Let's see if we got a new packet here
		p->total_packets++;

		p->last_seq = (p->last_seq + 1) & 0xF;
		while (p->last_seq != (mpeg_buff[3] & 0xF)) {
			p->last_seq = (p->last_seq + 1) & 0xF;
			p->missed_packets++;
			missing_parts = 1;
			packet_pos = 0;
		}


		if (missing_parts) { // If there are missing parts in the current docsis frame
			if (mpeg_buff[1] & 0x40) {
				packet_pos = MPEG_TS_LEN - mpeg_buff[4] - 5;
				if (packet_pos > bufflen) {
					dprint("Please increase your read buffer (needed %u, given %u)\n", packet_pos, bufflen);
					return 0;
				}
				memcpy(buffer, mpeg_buff + mpeg_buff[4] + 5, packet_pos);
				missing_parts = 0;
				
			} else { // Discard any other part
				p->dropped_packets++;
				continue;
			}


		} else if (mpeg_buff[1] & 0x40) { // There are no missing parts and we got a new packet. finish the previous one if needed
			
			if (mpeg_buff[4] > 0) {

				// Copy the first part in the provided buffer
				if (packet_pos + mpeg_buff[4] > bufflen) {
					dprint("Please increase your read buffer (needed %u, given %u)\n", packet_pos + mpeg_buff[4], bufflen);
					return 0;
				}
				memcpy(buffer + packet_pos, mpeg_buff + 5, mpeg_buff[4]);
				packet_pos += mpeg_buff[4];

			}

			// Copy the remaining part into our temp buffer
			p->temp_buff_pos = MPEG_TS_LEN - mpeg_buff[4] - 5;
			memcpy(p->temp_buff, mpeg_buff + mpeg_buff[4] + 5, p->temp_buff_pos);

			return packet_pos;


		} else {
			
			// Ok it's not a new packet. Let's append to what we already have

			if (packet_pos + MPEG_TS_LEN - 4 > bufflen) {
				dprint("Please increase your read buffer (needed %u, given %u)\n", packet_pos + MPEG_TS_LEN - 4, bufflen);
				return 0;
			}
			memcpy(buffer + packet_pos, mpeg_buff + 4, MPEG_TS_LEN - 4);
			packet_pos += MPEG_TS_LEN - 4;


		}
		
	


	} while(1);

	// Never reached
	return 0;
}

int input_close_docsis(struct input *i) {

	struct input_priv_docsis *p = i->input_priv;
	if (!p)
		return 0;
	
	close(p->frontend_fd);
	close(p->demux_fd);
	close(p->dvr_fd);

	dprint("0x%02x; DOCSIS : Total packet read %lu, missed %lu (%.1f%%), dropped %lu (%.1f%%), erroneous %lu (%.1f%%), invalid %lu (%.1f%%), total dropped %lu (%.1f%%)\n", \
		(unsigned int) i->input_priv, \
		p->total_packets, \
		p->missed_packets, \
		100.0 / (double) p->total_packets * (double) p->missed_packets, \
		p->dropped_packets, \
		100.0 / (double) p->total_packets * (double) p->dropped_packets, \
		p->error_packets, \
		100.0 / (double) p->total_packets * (double) p->error_packets, \
		p->invalid_packets, \
		100.0 / (double) p->total_packets * (double) p->invalid_packets, \
		p->missed_packets + p->dropped_packets + p->error_packets + p->invalid_packets, \
		100.0 / (double) p->total_packets * (double) (p->missed_packets + p->dropped_packets + p->error_packets + p->invalid_packets));




	return 1;

}
