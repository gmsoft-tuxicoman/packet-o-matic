/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006 Guy Martin <gmsoft@tuxicoman.be>
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

#include "common.h"
#include "conf.h"
#include "conntrack.h"
#include "helper.h"
#include "input.h"


#if defined DEBUG && defined HAVE_MCHECK_H
#include <mcheck.h>
#endif

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>




#define SNAPLEN 2000

int finish = 0;


void signal_handler(int signal) {
	
	dprint("Received signal. Finishing ... !\n");
	finish = 1;

}


void print_help() {
	
	printf("Usage : packet-o-matic [-c config_file] [-h]\n");

	char * path = getenv("LD_LIBRARY_PATH");

	if (!path)
		path = LIBDIR;


	DIR *d;
	d = opendir(path);
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

#if defined DEBUG && defined HAVE_MCHECK_H
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


	// Init the stuff
	layer_init();
	match_init();
	conntrack_init();
	helper_init();
	target_init();
	rules_init();

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

	// Set which rule list we want to use for helped packets
	helper_set_feedback_rules(c->rules);


	// Init the timer only now to avoid bothering with SIGALARM
	timers_init();
	
	// Install the signal handler
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	
	// Start reading from the docsis stream

	unsigned char packet[SNAPLEN];
	unsigned int len;
	int first_layer = input_get_first_layer(c->input);

	while (!finish) {
		len = input_read(c->input, packet, SNAPLEN);
		if (len == -1) {
			dprint("Error while reading. Abording\n");
			break;
		}
		timers_process(); // This is not real-time timers but we don't really need it
		if (len > 0)
			do_rules(packet, 0, len, c->rules, first_layer);
	}

	input_close(c->input);
	config_cleanup(c);

	conntrack_cleanup();
	helper_cleanup();
	timers_cleanup();
	target_cleanup();
	match_cleanup();
	layer_cleanup();


	target_unregister_all();
	match_unregister_all();
	conntrack_unregister_all();
	helper_unregister_all();
	input_unregister_all();


	return 0;
}
