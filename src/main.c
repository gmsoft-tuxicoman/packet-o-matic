/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007 Guy Martin <gmsoft@tuxicoman.be>
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
#include "mgmtsrv.h"
#include "ptype.h"

#include "main.h"


#if defined DEBUG && defined HAVE_MCHECK_H
#include <mcheck.h>
#endif

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>

#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

#define RINGBUFFER_SIZE 10000


int finish = 0;
pthread_mutex_t ringbuffer_mutex = PTHREAD_MUTEX_INITIALIZER; ///< Mutex of the circle buffer
pthread_cond_t ringbuffer_underrun_cond = PTHREAD_COND_INITIALIZER; ///< Condition wait of the circle buffer when it's empty
pthread_cond_t ringbuffer_overflow_cond = PTHREAD_COND_INITIALIZER; ///< Condition wait of the circle buffer when it's full and we don't have to drop packets
unsigned long ringbuffer_dropped_packets = 0; ///< Count the dropped packets
unsigned long ringbuffer_total_packets = 0; ///< Count the total number of packet that went trough the buffer

pthread_mutex_t reader_mutex = PTHREAD_MUTEX_INITIALIZER; ///< Mutex used to lock the reader thread if changes are made or modules are loaded/unloaded

struct frame* ringbuffer[RINGBUFFER_SIZE];
unsigned int ringbuffer_read_pos; // Where the process thread WILL read the packets
unsigned int ringbuffer_write_pos; // Where the input thread is CURRENTLY writing
unsigned int ringbuffer_usage = 0; // Number of packet in the buffer waiting to be processed


struct timeval now; ///< Used to get the current time from the input perspective

void signal_handler(int signal) {
	
	dprint("Received signal. Finishing ... !\n");
	finish = 1;

}


void print_usage() {

	printf(	"Usage : packet-o-matic [options]\n"
		"\n"
		"Options :\n"
		" -c, --config=FILE          specify configuration file to use (default pom.xml.conf)\n"
		" -h, --help                 display the help\n"
		"   , --no-cli               disable the CLI console\n"
		" -p, --port=PORT            specify the CLI console port (default 4655)\n"
		" -w, --password=PASSWORD    specify a password to enter the CLI console\n"
		"\n"
		);
	

}

void print_help() {

	print_usage();

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


void *mgmtsrv_thread_func(void *params) {

	while (!finish) {
		mgmtsrv_process();
	}
	return NULL;
}

void *input_thread_func(void *params) {

	struct input_thread_params *p = params;

	while (!finish) {


		if (input_read(p->i, ringbuffer[ringbuffer_write_pos]) == POM_ERR) {
			dprint("Error while reading. Abording\n");
			break;
		}
		ringbuffer_total_packets++;

		pthread_mutex_lock(&ringbuffer_mutex);
		ringbuffer_usage++;

		if (ringbuffer_usage == 1) {
			pthread_cond_signal(&ringbuffer_underrun_cond);
		}

		while (ringbuffer_usage >= RINGBUFFER_SIZE - 1) {
			if (p->input_is_live) {
				ndprint("Buffer overflow (%u). droping packet\n", ringbuffer_usage);
				ringbuffer_write_pos--;
				ringbuffer_dropped_packets++;
				ringbuffer_usage--;
				break;
			} else {
				ndprint("Buffer is full. Waiting\n");
				if(pthread_cond_wait(&ringbuffer_overflow_cond, &ringbuffer_mutex)) {
					dprint("Failed to wait for buffer to empty out\n");
					pthread_mutex_unlock(&ringbuffer_mutex);
					pthread_exit(NULL);
				}
				ndprint("waiting over\n");
			}
		}

		ringbuffer_write_pos++;
		if (ringbuffer_write_pos >= RINGBUFFER_SIZE)
			ringbuffer_write_pos = 0;

		pthread_mutex_unlock(&ringbuffer_mutex);

	}


	finish = 1;

	//pthread_exit(NULL);
	return NULL;
}


int main(int argc, char *argv[]) {

#if defined DEBUG && defined HAVE_MCHECK_H
	mtrace();
#endif

	char *cfgfile = "pom.xml.conf";
	int disable_mgmtsrv = 0;
	char *cli_port = "4655";

	int c;

	while (1) {
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "conf", 1, 0, 'c'},
			{ "port", 1, 0, 'p'},
			{ "password", 1, 0, 'w'},
			{ "no-cli", 0, 0, 1},
			{ 0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hc:p:w:", long_options, NULL);

		if (c == -1)
			break;

		switch(c) {
			case 1:
				disable_mgmtsrv = 1;
				dprint("Not starting CLI console because of --no-cli flag\n");
				break;
			case 'h':
				match_init();
				target_init();
				print_help();
				match_cleanup();
				target_cleanup();
				return 0;
			case 'c':
				cfgfile = optarg;
				dprint("Config file is %s\n", optarg);
				break;
			case 'p':
				cli_port = optarg;
				dprint("Using port %s for CLI console\n", cli_port);
				break;
			case 'w':
				mgmtsrv_set_password(optarg);
				dprint("CLI is password protected\n");
				break;
			case '?':
			default:
				print_usage();
				return 1;

		}
	}


	// Init the stuff
	layer_init();
	match_init();
	conntrack_init();
	helper_init();
	target_init();
	rules_init();
	ptype_init();


	main_config = config_alloc();

	if (!config_parse(main_config, cfgfile)) {
		dprint("Error while parsing config\n");
		goto err;
	}

	if (!disable_mgmtsrv && mgmtsrv_init(cli_port) == POM_ERR) {
		dprint("Error when initializing the management console. Abording\n");
		goto err;
	}
	int fd = input_open(main_config->input);

	if (fd == POM_ERR) {
		dprint("Error while opening input\n");
		goto err;
	}

	struct input_caps ic;
	if (input_getcaps(main_config->input, &ic) == POM_ERR) {
		dprint("Error while getting input capabilities\n");
		goto err;
	}

	// Install the signal handler
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);
	
	// Initialize the ring buffer
	dprint("Using %u buffers of %u bytes\n", RINGBUFFER_SIZE, ic.snaplen);
	int i;
	for (i = 0; i < RINGBUFFER_SIZE; i++) {
		ringbuffer[i] = malloc(sizeof(struct frame));
		bzero(ringbuffer[i], sizeof(struct frame));
		ringbuffer[i]->buff = malloc(ic.snaplen);
		ringbuffer[i]->bufflen = ic.snaplen;
		ringbuffer[i]->input = main_config->input;

	}
	ringbuffer_read_pos = RINGBUFFER_SIZE - 1;
	ringbuffer_write_pos = 0;

	struct input_thread_params itp;
	itp.i = main_config->input;
	itp.input_is_live = ic.is_live;

	pthread_t input_thread;
	if (pthread_create(&input_thread, NULL, input_thread_func, (void*)&itp)) {
		dprint("Error when creating the input thread. Abording\n");
		goto finish;
	}
	
	pthread_t mgmtsrv_thread;
	if (!disable_mgmtsrv && pthread_create(&mgmtsrv_thread, NULL, mgmtsrv_thread_func, NULL)) {
		dprint("Error when creating the management console thread. Abording\n");
		goto err;
	}


	struct sched_param sp;
	sp.sched_priority = 5;

	if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp)) {
		dprint("Error while setting input thread priority\n");
	}

	if (pthread_mutex_lock(&ringbuffer_mutex)) {
		dprint("Error while locking the buffer mutex. Abording\n");
		goto finish;
	}

	// wait for at least one packet to be available
	while (ringbuffer_usage <= 0) {
		if (finish) {
			pthread_mutex_unlock(&ringbuffer_mutex);
			goto finish;
		}
		ndprint("Buffer empty (%u). Waiting\n", ringbuffer_usage);
		struct timeval tv;
		gettimeofday(&tv, NULL);
		struct timespec tp;
		tp.tv_sec = tv.tv_sec + 3;
		tp.tv_nsec = tv.tv_usec * 1000;
		switch (pthread_cond_timedwait(&ringbuffer_underrun_cond, &ringbuffer_mutex, &tp)) {
			case ETIMEDOUT:
				dprint("timeout occured\n");
			case 0:
				break;
			default:
				dprint("Error occured while waiting for next frame to be available\n");
				pthread_mutex_unlock(&ringbuffer_mutex);
				goto finish;

		}
	}
	if (pthread_mutex_unlock(&ringbuffer_mutex)) {
		dprint("Error while unlocking the buffer mutex. Abording\n");
		goto finish;
	}


	while (!finish) {

		if (ic.is_live)
			gettimeofday(&now, NULL);

		if (pthread_mutex_lock(&reader_mutex)) {
			dprint("Error while locking the reader mutex. Abording\n");
			goto finish;
		}
	
		timers_process(); // This is not real-time timers but we don't really need it
		if (ringbuffer[ringbuffer_read_pos]->len > 0) // Need to queue that in the buffer
			do_rules(ringbuffer[ringbuffer_read_pos], main_config->rules);

		if (!ic.is_live) {
			memcpy(&now, &ringbuffer[ringbuffer_read_pos]->tv, sizeof(struct timeval));
			now.tv_usec += 1;
		}


		helper_process_queue(main_config->rules); // Process frames that needed some help


		if (pthread_mutex_unlock(&reader_mutex)) {
			dprint("Error while locking the reader mutex. Abording\n");
			goto finish;
		}


		if (pthread_mutex_lock(&ringbuffer_mutex)) {
			dprint("Error while locking the buffer mutex. Abording\n");
			goto finish;
		}
		ringbuffer_usage--;
		if (!ic.is_live && ringbuffer_usage <= RINGBUFFER_SIZE - 1)
			pthread_cond_signal(&ringbuffer_overflow_cond);

		ringbuffer_read_pos++;
		if (ringbuffer_read_pos >= RINGBUFFER_SIZE)
			ringbuffer_read_pos = 0;


		while (ringbuffer_usage <= 0) {
			if (finish) {
				pthread_mutex_unlock(&ringbuffer_mutex);
				goto finish;
			}
			ndprint("Buffer empty (%u). Waiting\n", ringbuffer_usage);
			struct timeval tv;
			gettimeofday(&tv, NULL);
			struct timespec tp;
			tp.tv_sec = tv.tv_sec + 3;
			tp.tv_nsec = tv.tv_usec * 1000;
			switch (pthread_cond_timedwait(&ringbuffer_underrun_cond, &ringbuffer_mutex, &tp)) {
				case ETIMEDOUT:
					ndprint("timeout occured\n");
				case 0:
					break;
				default:
					dprint("Error occured while waiting for next frame to be available\n");
					pthread_mutex_unlock(&ringbuffer_mutex);
					goto finish;

			}
		}
		
		if (pthread_mutex_unlock(&ringbuffer_mutex)) {
			dprint("Error while unlocking the buffer mutex. Abording\n");
			goto finish;
		}
	



	}

finish:
	finish = 1;
	pthread_join(input_thread, NULL);
	if (!disable_mgmtsrv)
		pthread_join(mgmtsrv_thread, NULL);

	dprint("Total packets read : %lu, dropped %lu (%.2f%%)\n", ringbuffer_total_packets, ringbuffer_dropped_packets, 100.0 / ringbuffer_total_packets * ringbuffer_dropped_packets);

	// Process remaining queued frames
	conntrack_close_connections(main_config->rules);

	input_close(main_config->input);

	for (i = 0; i < RINGBUFFER_SIZE; i++) {
		free(ringbuffer[i]->buff);
		free(ringbuffer[i]);

	}
err:

	config_cleanup(main_config);

	helper_unregister_all();
	helper_cleanup();

	conntrack_cleanup();
	timers_cleanup();
	target_cleanup();

	if (!disable_mgmtsrv)
		mgmtsrv_cleanup();

	target_unregister_all();
	
	match_unregister_all();
	match_cleanup();

	conntrack_unregister_all();
	input_unregister_all();
	ptype_unregister_all();

	// Layers need to be cleaned up after the match
	layer_cleanup();

	return 0;
}

int reader_process_lock() {
	return pthread_mutex_lock(&reader_mutex);
}

int reader_process_unlock() {
	return pthread_mutex_unlock(&reader_mutex);
}

int get_current_input_time(struct timeval *cur_time) {

	memcpy(cur_time, &now, sizeof(struct timeval));
	return 0;
}

