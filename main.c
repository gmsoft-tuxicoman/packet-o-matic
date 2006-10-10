
#ifdef DEBUG
#include <mcheck.h>
#endif

#include <signal.h>

#include "common.h"
#include "conf.h"
#include "input_docsis.h"
#include "input_pcap.h"
#include "conntrack.h"

#define SNAPLEN 2000

int finish = 0;


void signal_handler(int signal) {
	
	dprint("Received signal. Finishing ... !\n");
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

#ifdef DEBUG
	mtrace();
#endif


	conntrack_init();

	struct conf *c = config_alloc();

	if (!config_parse(c, "pom.xml.conf")) {
		dprint("Error while parsing config\n");
		config_cleanup(c);
		return 1;
	}

	if (!input_open(c->input)) {
		dprint("Error while opening input\n");
		return 1;
	}
	
//	struct rule_list *rules;
//	rules = do_config();
	
	// Install the signal handler
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	
	// Start reading from the docsis stream

	unsigned char packet[SNAPLEN];
	unsigned int len;

	while (!finish) {
		len = input_read(c->input, packet, SNAPLEN);
		if (len == -1) {
			dprint("Error while reading. Abording\n");
			break;
		}

		process_packet(packet, len, c->rules);
	}

	input_close(c->input);

	conntrack_cleanup();
	config_cleanup(c);


	target_unregister_all();
	match_unregister_all();
	conntrack_unregister_all();
	input_unregister_all();


	return 0;
}
