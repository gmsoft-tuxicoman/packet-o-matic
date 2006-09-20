

#ifndef __INPUT_DOCSIS_H__
#define __INPUT_DOCSIS_H__



#include <linux/dvb/frontend.h>

#include "common.h"
#include "input.h"


#define DEMUX "/dev/dvb/adapter0/demux0"
#define FRONT "/dev/dvb/adapter0/frontend0"
#define DVR "/dev/dvb/adapter0/dvr0"

#define DOCSIS_PID 0x1FFE

#define MPEG_TS_LEN 188

#define TEMP_BUFF_LEN 2000


struct input_open_docsis_params {

	int eurodocsis; // Is eurodocsis ?
	uint32_t frequency; // If 0 -> scan for downstream
	fe_modulation_t modulation; // What modulation to use

};

struct input_priv_docsis {

	int frontend_fd;
	int demux_fd;
	int dvr_fd;
	char temp_buff[TEMP_BUFF_LEN];
	unsigned int temp_buff_pos;
	unsigned char last_seq;
	unsigned long total_packets;
	unsigned long missed_packets;
	unsigned long error_packets;
	unsigned long dropped_packets;
	unsigned long invalid_packets;


};


int input_init_docsis(struct input *i);
int input_open_docsis(struct input *i, void *params);
int input_read_docsis(struct input *i, unsigned char *buffer, unsigned int bufflen);
int input_close_docsis(struct input *i);
int input_cleanup_docsis(struct input *i);

int input_docsis_scan_downstream(int eurodocsis);
int input_docsis_tune(struct input *i, uint32_t frequency, uint32_t symboleRate, fe_modulation_t modulation);
int input_docsis_check_downstream(struct input *i);

#endif

