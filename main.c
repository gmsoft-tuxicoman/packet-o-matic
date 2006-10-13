
#ifdef DEBUG
#include <mcheck.h>
#endif

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>


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

void print_help() {
	
	printf("Usage : packet-o-matic [-c config_file] [-h]\n");

	DIR *d;
	d = opendir("./");
	if (!d) {
		printf("No module found.\n");
		return;
	}

	struct dirent *dp;
	char type[NAME_MAX];

	while ((dp = readdir(d))) {

		if (sscanf(dp->d_name, "input_%s", type) == 1) {
			while (strlen(type) > 0) {
				if (type[strlen(type) - 1] == '.') {
					type[strlen(type) - 1] = 0;
					break;
				}
				type[strlen(type) - 1] = 0;
			}
			input_register(type);
		}

		if (sscanf(dp->d_name, "target_%s", type) == 1) {
			while (strlen(type) > 0) {
				if (type[strlen(type) - 1] == '.') {
					type[strlen(type) - 1] = 0;
					break;
				}
				type[strlen(type) - 1] = 0;
			}
			target_register(type);
		}

		if (sscanf(dp->d_name, "match_%s", type) == 1) {
			while (strlen(type) > 0) {
				if (type[strlen(type) - 1] == '.') {
					type[strlen(type) - 1] = 0;
					break;
				}
				type[strlen(type) - 1] = 0;
			}
			match_register(type);
		}
	}


	printf("\nINPUTS :\n--------\n\n");
	input_print_help();

	printf("\nTARGETS :\n---------\n\n");
	target_print_help();

	printf("\nMATCHS :\n-------\n\n");
	match_print_help();

}

int main(int argc, char *argv[]) {

#ifdef DEBUG
	mtrace();
#endif

	char *cfgfile = "pom.xml.conf";

	int o;

	while ((o = getopt(argc, argv, "hc:")) != -1 ) {
		switch(o) {
			case 'h':
				print_help();
				return 0;
			case 'c':
				cfgfile = optarg;
				dprint("Config file is %s\n", optarg);
				break;
			case '?':
				print_help();
				return 1;
			default:
				abort();

		}
	}


	// Conntrack must be initialized before registering any conntrack
	conntrack_init();

	struct conf *c = config_alloc();

	if (!config_parse(c, cfgfile)) {
		dprint("Error while parsing config\n");
		config_cleanup(c);
		return 1;
	}

	if (!input_open(c->input)) {
		dprint("Error while opening input\n");
		return 1;
	}
	
	
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
