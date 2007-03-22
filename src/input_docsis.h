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


#define DOCSIS_PID 0x1FFE

#define MPEG_TS_LEN 188

#define TEMP_BUFF_LEN 2000


struct input_priv_docsis {

	int frontend_fd;
	int demux_fd;
	int dvr_fd;
	unsigned char *temp_buff;
	int output_layer;
	unsigned int temp_buff_len;
	unsigned char last_seq;

	// stats stuff
	unsigned long total_packets;
	unsigned long missed_packets;
	unsigned long error_packets;
	unsigned long invalid_packets;


};


int input_init_docsis(struct input *i);
int input_open_docsis(struct input *i);
int input_get_first_layer_docsis(struct input *i);
int input_read_docsis(struct input *i, unsigned char *buffer, unsigned int bufflen);
int input_close_docsis(struct input *i);
int input_cleanup_docsis(struct input *i);

int input_docsis_read_mpeg_frame(unsigned char *buff, struct input_priv_docsis *p);
int input_docsis_scan_downstream(int eurodocsis);
int input_docsis_tune(struct input *i, uint32_t frequency, uint32_t symboleRate, fe_modulation_t modulation);
int input_docsis_check_downstream(struct input *i);

#endif

