
#include <signal.h>

#include "common.h"
#include "input_docsis.h"
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
		

}


int main(int argc, char *argv[]) {


	


	struct rule_list *rules;
	rules = do_config();


	struct input_open_docsis_params docsis_p;
	docsis_p.eurodocsis = 1;
	docsis_p.frequency = 442000000;
	docsis_p.modulation = QAM_256;

	int docsis_input_type = input_register("docsis");

	if (docsis_input_type == -1)
		return 1;

	struct input *docsis_input = input_alloc(docsis_input_type);
	if (!input_open(docsis_input, &docsis_p)) {
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
		len = input_read(docsis_input, packet, SNAPLEN);
		if (len == -1) {
			dprint("Error while reading. Abording\n");
			break;
		}

		process_packet(packet, len, rules);
	}
	input_close(docsis_input);
	input_cleanup(docsis_input);


	list_destroy(rules);

	target_unregister_all();
	match_unregister_all();
	input_unregister_all();


	return 0;
}
