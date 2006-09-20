
#include <signal.h>

#include "common.h"
#include "input_docsis.h"
#include "input_pcap.h"
#include "config.h"

#define SNAPLEN 2000

int finish = 0;


void signal_handler(int signal) {
	
	printf("Received signal. Finishing ... !\n");
	finish = 1;

}

void process_packet(unsigned char* packet, unsigned int  len, struct rule_list *rules) {

	// If packet is empty, skip
	if (len == 0)
		return;

	// Byte 0 and 1 are set to 0 if it's an ethernet packet. If not, skip it
	if (packet[0] || packet[1]) {
		return;
	}
	do_rules(packet+ 6, 0, len - 6, rules);
		
	do_rules(packet, 0, len,  rules);

}


int main(int argc, char *argv[]) {



	struct rule_list *rules;
	rules = do_config();

	struct input_open_docsis_params op;
	op.eurodocsis = 1;
	op.frequency = 442000000;
	op.modulation = QAM_256;

	int input_type = input_register("docsis");
/*
	struct input_open_pcap_params op;
	op.filename = 0;
	op.interface = "wlan0";
	op.snaplen = 1500;
	op.promisc = 0;

	int input_type = input_register("pcap");
*/
	if (input_type == -1)
		return 1;

	struct input *in = input_alloc(input_type);
	if (!input_open(in, &op)) {
		dprint("Error while opening input\n");
		return 1;
	};


	
	
	// Install the signal handler
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	
	// Start reading from the docsis stream

	unsigned char packet[SNAPLEN];
	unsigned int len;

	while (!finish) {
		len = input_read(in, packet, SNAPLEN);
		if (len == -1) {
			dprint("Error while reading. Abording\n");
			break;
		}

		process_packet(packet, len, rules);
	}
	input_close(in);
	input_cleanup(in);


	list_destroy(rules);

	target_unregister_all();
	match_unregister_all();
	input_unregister_all();


	return 0;
}
