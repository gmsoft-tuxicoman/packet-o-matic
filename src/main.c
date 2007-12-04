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

#include "ptype_bool.h"
#include "ptype_uint32.h"

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


pthread_mutex_t reader_mutex = PTHREAD_MUTEX_INITIALIZER; ///< Mutex used to lock the reader thread if changes are made or modules are loaded/unloaded
pthread_t input_thread;

int finish = 0;

struct timeval now; ///< Used to get the current time from the input perspective

void signal_handler(int signal) {
	
	pom_log("Received signal. Finishing ... !\r\n");
	finish = 1;
	if (rbuf->state != rb_state_closed)
		rbuf->state = rb_state_stopping;

}


void print_usage() {

	printf(	"Usage : packet-o-matic [options]\n"
		"\n"
		"Options :\n"
		" -c, --config=FILE          specify configuration file to use (default pom.xml.conf)\n"
		" -e, --empty-config         start with an empty config\n"
		" -h, --help                 display the help\n"
		"     --no-cli               disable the CLI console\n"
		" -p, --port=PORT            specify the CLI console port (default 4655)\n"
		" -w, --password=PASSWORD    specify a password to enter the CLI console\n"
		" -d, --debug-level=LEVEL    specify the debug level <1-4> (default 3)\n"
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

	closedir(d);

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

int start_input(struct ringbuffer *r) {


	if (r->state != rb_state_closed) {
		pom_log(POM_LOG_WARN "Input already started or being started\r\n");
		return POM_ERR;
	}

	if (pthread_mutex_lock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording\r\n");
		return POM_ERR;
	}

	r->state = rb_state_opening;

	int fd = input_open(main_config->input);

	if (fd == POM_ERR) {
		pom_log(POM_LOG_ERR "Error while opening input\r\n");
		r->state = rb_state_closed;
		pthread_mutex_unlock(&r->mutex);
		return POM_ERR;
	}

	if (ringbuffer_alloc(r, main_config->input) == POM_ERR) {
		pom_log(POM_LOG_ERR "Error while allocating the ringbuffer\r\n");
		input_close(r->i);
		r->state = rb_state_closed;
		pthread_mutex_unlock(&r->mutex);
		return POM_ERR;
	}

	r->state = rb_state_open;


	if (pthread_create(&input_thread, NULL, input_thread_func, (void*)r)) {
		pom_log(POM_LOG_ERR "Error when creating the input thread. Abording\r\n");
		input_close(r->i);
		r->state = rb_state_closed;
		return POM_ERR;
	}
	
	if (pthread_mutex_unlock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording\r\n");
		input_close(r->i);
		r->state = rb_state_closed;
		return POM_ERR;
	}
	return POM_OK;

}

int stop_input(struct ringbuffer *r) {

	if (r->state != rb_state_open) {
		pom_log(POM_LOG_WARN "Input not yet started\r\n");
		return POM_ERR;
	}

	if (pthread_mutex_lock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording\r\n");
		return POM_ERR;
	}

	r->state = rb_state_stopping;

	if (pthread_mutex_unlock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording\r\n");
		return POM_ERR;
	}

	pthread_join(input_thread, NULL);

	return POM_OK;

}

void *input_thread_func(void *params) {

	struct ringbuffer *r = params;


	if (pthread_mutex_lock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording\r\n");
		finish = 1;
		return NULL;
	}

	pom_log(POM_LOG_DEBUG "Input thead started\r\n");

	while (r->state == rb_state_open) {

		if (pthread_mutex_unlock(&r->mutex)) {
			pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording\r\n");
			finish = 1;
			return NULL;
		}

		if (input_read(r->i, r->buffer[r->write_pos]) == POM_ERR) {
			pom_log(POM_LOG_ERR "Error while reading from input\r\n");
			r->state = rb_state_closing;
			// We need to aquire the lock
			pthread_mutex_lock(&r->mutex);
			break;
		}

		if (pthread_mutex_lock(&r->mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording\r\n");
			finish = 1;
			return NULL;
		}

		if (r->buffer[r->write_pos]->len == 0)
			continue;

		r->total_packets++;
		r->usage++;

		if (r->usage == 1) {
			pthread_cond_signal(&r->underrun_cond);
		}

		while (r->usage >= PTYPE_UINT32_GETVAL(r->size) - 1) {
			if (r->ic.is_live) {
				//pom_log(POM_LOG_TSHOOT "Buffer overflow (%u). droping packet\r\n", r->usage);
				r->write_pos--;
				r->dropped_packets++;
				r->usage--;
				break;
			} else {
				//pom_log(POM_LOG_TSHOOT "Buffer is full. Waiting\r\n");
				if(pthread_cond_wait(&r->overflow_cond, &r->mutex)) {
					pom_log(POM_LOG_ERR "Failed to wait for buffer to empty out\r\n");
					pthread_mutex_unlock(&r->mutex);
					pthread_exit(NULL);
				}
			}
		}

		r->write_pos++;
		if (r->write_pos >= PTYPE_UINT32_GETVAL(r->size))
			r->write_pos = 0;


	}

	input_close(r->i);

	while (r->usage > 0) {
		pthread_mutex_unlock(&r->mutex);
		pom_log(POM_LOG_TSHOOT "Waiting for ringbuffer to be empty\r\n");
		usleep(50000);
		pthread_mutex_lock(&r->mutex);
		
	}

	ringbuffer_cleanup(r);

	if (pthread_mutex_unlock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording\r\n");
		finish = 1;
		return NULL;
	}
	r->state = rb_state_closed;

	pom_log(POM_LOG_DEBUG "Input thread stopped\r\n");

	return NULL;
}


int main(int argc, char *argv[]) {

#if defined DEBUG && defined HAVE_MCHECK_H
	mtrace();
#endif

	core_params = NULL;

	debug_level = *POM_LOG_INFO;

	char *cfgfile = "pom.xml.conf";
	int empty_config = 0;
	int disable_mgmtsrv = 0;
	char *cli_port = "4655";

	int c;

	while (1) {
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "config", 1, 0, 'c'},
			{ "empty-config", 0, 0, 'e'},
			{ "port", 1, 0, 'p'},
			{ "password", 1, 0, 'w'},
			{ "no-cli", 0, 0, 1},
			{ "debug-level", 1, 0, 'd'},
			{ 0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hc:ep:w:d:", long_options, NULL);

		if (c == -1)
			break;

		switch(c) {
			case 1:
				disable_mgmtsrv = 1;
				pom_log("Not starting CLI console because of --no-cli flag\r\n");
				break;
			case 'h':
				ptype_init();
				match_init();
				target_init();
				conntrack_init();
				helper_init();
				print_help();
				input_unregister_all();
				conntrack_unregister_all();
				helper_unregister_all();
				helper_cleanup();
				conntrack_unregister_all();
				conntrack_cleanup();
				match_unregister_all();
				match_cleanup();
				target_unregister_all();
				target_cleanup();
				core_param_unregister_all();
				ptype_unregister_all();
				return 0;
			case 'c':
				cfgfile = optarg;
				pom_log("Config file is %s\r\n", optarg);
				break;
			case 'e':
				empty_config = 1;
				pom_log("Starting with an empty configuration\r\n");
				break;
			case 'p':
				cli_port = optarg;
				pom_log("Using port %s for CLI console\r\n", cli_port);
				break;
			case 'w':
				mgmtsrv_set_password(optarg);
				pom_log("CLI is password protected\r\n");
				break;
			case 'd':
				if (sscanf(optarg, "%u", &debug_level) == 1) {
					printf("Debug level set to %u\n", debug_level);
					break;
				} else {
					printf("Invalid debug level \"%s\"\n", optarg);
				}
			case '?':
			default:
				print_usage();
				return 1;

		}
	}


	// Init the stuff
	ptype_init();
	layer_init();
	match_init();
	conntrack_init();
	helper_init();
	target_init();
	rules_init();


	struct ptype *param_autosave_on_exit = ptype_alloc("bool", NULL);
	if (!param_autosave_on_exit) {
		pom_log(POM_LOG_ERR "Cannot allocate ptype bool. Abording\r\n");
		return -1;
	}
	core_register_param("autosave_config_on_exit", "yes", param_autosave_on_exit, "Automatically save the configuration when exiting", NULL);


	rbuf = malloc(sizeof(struct ringbuffer));

	if (ringbuffer_init(rbuf) == POM_ERR) {
		goto finish;
	}

	// Install the signal handler
	signal(SIGHUP, signal_handler);
	signal(SIGINT, signal_handler);

	main_config = config_alloc();
	if (empty_config) {
		strncpy(main_config->filename, cfgfile, NAME_MAX);
	} else {
		if (config_parse(main_config, cfgfile) == POM_ERR) {
			pom_log(POM_LOG_ERR "Error while parsing config\r\n");
			goto err;
		}
	}

	if (!disable_mgmtsrv && mgmtsrv_init(cli_port) == POM_ERR) {
		pom_log(POM_LOG_ERR "Error when initializing the management console. Abording\r\n");
		goto err;
	}

	pthread_t mgmtsrv_thread;
	if (!disable_mgmtsrv && pthread_create(&mgmtsrv_thread, NULL, mgmtsrv_thread_func, NULL)) {
		pom_log(POM_LOG_ERR "Error when creating the management console thread. Abording\r\n");
		goto err;
	}

	if (main_config->input && start_input(rbuf) == POM_ERR) {
		pom_log(POM_LOG_ERR "Error when starting the input. Abording\r\n");
		goto err;
	}

	if (pthread_mutex_lock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording\r\n");
		goto finish;
	}

	// wait for at least one packet to be available
	while (rbuf->usage <= 0) {
		if (finish) {
			pthread_mutex_unlock(&rbuf->mutex);
			goto finish;
		}
		//pom_log(POM_LOG_TSHOOT "Buffer empty (%u). Waiting\r\n", rbuf->usage);
		struct timeval tv;
		gettimeofday(&tv, NULL);
		struct timespec tp;
		tp.tv_sec = tv.tv_sec + 3;
		tp.tv_nsec = tv.tv_usec * 1000;
		switch (pthread_cond_timedwait(&rbuf->underrun_cond, &rbuf->mutex, &tp)) {
			case ETIMEDOUT:
			case 0:
				break;
			default:
				pom_log(POM_LOG_ERR "Error occured while waiting for next frame to be available\r\n");
				pthread_mutex_unlock(&rbuf->mutex);
				goto finish;

		}
	}


	while (rbuf->usage > 0) {

		
		if (pthread_mutex_unlock(&rbuf->mutex)) {
			pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording\r\n");
			goto finish;
		}
	
		if (rbuf->ic.is_live)
			gettimeofday(&now, NULL);

		if (pthread_mutex_lock(&reader_mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the reader mutex. Abording\r\n");
			goto finish;
		}
	
		timers_process(); // This is not real-time timers but we don't really need it
		if (rbuf->buffer[rbuf->read_pos]->len > 0) // Need to queue that in the buffer
			do_rules(rbuf->buffer[rbuf->read_pos], main_config->rules);

		if (!rbuf->ic.is_live) {
			memcpy(&now, &rbuf->buffer[rbuf->read_pos]->tv, sizeof(struct timeval));
			now.tv_usec += 1;
		}


		helper_process_queue(main_config->rules); // Process frames that needed some help


		if (pthread_mutex_unlock(&reader_mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the reader mutex. Abording\r\n");
			goto finish;
		}


		if (pthread_mutex_lock(&rbuf->mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording\r\n");
			goto finish;
		}
		rbuf->usage--;
		if (!rbuf->ic.is_live && rbuf->usage <= PTYPE_UINT32_GETVAL(rbuf->size) - 1)
			pthread_cond_signal(&rbuf->overflow_cond);

		rbuf->read_pos++;
		if (rbuf->read_pos >= PTYPE_UINT32_GETVAL(rbuf->size))
			rbuf->read_pos = 0;


		while (rbuf->usage <= 0) {
			if (finish && rbuf->state == rb_state_closed) {
				pthread_mutex_unlock(&rbuf->mutex);
				goto finish;
			}
			//pom_log(POM_LOG_TSHOOT "Buffer empty (%u). Waiting\r\n", rbuf->usage);
			struct timeval tv;
			gettimeofday(&tv, NULL);
			struct timespec tp;
			tp.tv_sec = tv.tv_sec + 3;
			tp.tv_nsec = tv.tv_usec * 1000;
			switch (pthread_cond_timedwait(&rbuf->underrun_cond, &rbuf->mutex, &tp)) {
				case ETIMEDOUT:
					pom_log(POM_LOG_TSHOOT "Timeout occured while waiting for next frame to be available\r\n");
				case 0:
					break;
				default:
					pom_log(POM_LOG_ERR "Error occured while waiting for next frame to be available\r\n");
					pthread_mutex_unlock(&rbuf->mutex);
					goto finish;

			}
		}



	}

finish:
	finish = 1;
	if (rbuf->i)
		stop_input(rbuf);

	if (!disable_mgmtsrv)
		pthread_join(mgmtsrv_thread, NULL);

	pom_log("Total packets read : %lu, dropped %lu (%.2f%%)\r\n", rbuf->total_packets, rbuf->dropped_packets, 100.0 / rbuf->total_packets * rbuf->dropped_packets);

	// Process remaining queued frames
	conntrack_close_connections(main_config->rules);

	if (PTYPE_BOOL_GETVAL(param_autosave_on_exit)) {
		pom_log("Autosaving configuration to %s\r\n", main_config->filename);
		config_write(main_config, main_config->filename);
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

	// Layers need to be cleaned up after the match
	layer_cleanup();

	ringbuffer_deinit(rbuf);
	free(rbuf);
	ptype_cleanup_module(param_autosave_on_exit);
	core_param_unregister_all();

	ptype_unregister_all();

	return 0;
}

int ringbuffer_init(struct ringbuffer *r) {
	bzero(r, sizeof(struct ringbuffer));
	pthread_mutex_init(&r->mutex, NULL);
	pthread_cond_init(&r->underrun_cond, NULL);
	pthread_cond_init(&r->overflow_cond, NULL);

	r->size = ptype_alloc("uint32", "packets");
	if (!r->size)
		return POM_ERR;

	core_register_param("ringbuffer_size", "10000", r->size, "Number of packets to hold in the ringbuffer", ringbuffer_can_change_size);

	return POM_OK;

}

int ringbuffer_deinit(struct ringbuffer *r) {

	if (!r)
		return POM_ERR;

	ptype_cleanup_module(r->size);
	return POM_OK;
}

int ringbuffer_alloc(struct ringbuffer *r, struct input *in) {

	r->i = in;

	if (input_getcaps(r->i, &r->ic) == POM_ERR) {
		pom_log(POM_LOG_ERR "Error while getting input capabilities\r\n");
		return POM_ERR;
	}

	// Initialize the ring buffer
	pom_log(POM_LOG_DEBUG "Using %u buffers of %u bytes\r\n", PTYPE_UINT32_GETVAL(r->size), r->ic.snaplen);

	r->buffer = malloc(sizeof(struct frame*) * PTYPE_UINT32_GETVAL(r->size));

	int i;
	for (i = 0; i < PTYPE_UINT32_GETVAL(r->size); i++) {
		r->buffer[i] = malloc(sizeof(struct frame));
		bzero(r->buffer[i], sizeof(struct frame));
		r->buffer[i]->buff = malloc(r->ic.snaplen);
		r->buffer[i]->bufflen = r->ic.snaplen;
		r->buffer[i]->input = main_config->input;

	}
	r->read_pos = PTYPE_UINT32_GETVAL(r->size) - 1;
	r->write_pos = 0;

	return POM_OK;

}

int ringbuffer_cleanup(struct ringbuffer *r) {

	int i;

	for (i = 0; i < PTYPE_UINT32_GETVAL(r->size); i++) {
		free(r->buffer[i]->buff);
		free(r->buffer[i]);
	}
	free(r->buffer);

	return POM_OK;
}

int ringbuffer_can_change_size(struct ptype *value, char *msg, size_t size) {

	if (rbuf->state != rb_state_closed) {
		strncpy(msg, "Input must be stopped in order to changed the buffer size", size);
		return POM_ERR;
	}

	return POM_OK;

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

int halt() {

	pom_log("Stopping application ...\r\n");
	finish = 1;
	if (rbuf->state != rb_state_closed)
		rbuf->state = rb_state_stopping;
	return POM_OK;
}

int core_register_param(char *name, char *defval, struct ptype *value, char *descr, int (*param_can_change) (struct ptype *value, char *msg, size_t size)) {

	struct core_param *p = malloc(sizeof(struct core_param));
	bzero(p, sizeof(struct core_param));

	p->name = malloc(strlen(name) + 1);
	strcpy(p->name, name);
	p->defval = malloc(strlen(defval) + 1);
	strcpy(p->defval, defval);
	p->descr = malloc(strlen(descr) + 1);
	strcpy(p->descr, descr);
	p->value = value;

	p->can_change = param_can_change;

	if (ptype_parse_val(p->value, defval) == POM_ERR)
		return POM_ERR;

	p->next = core_params;
	core_params = p;

	return POM_OK;

}

struct ptype* core_get_param_value(char *param) {

	struct core_param *p = core_params;
	while (p) {
		if (!strcmp(p->name, param))
			return p->value;
		p = p->next;
	}

	return NULL;

}

int core_set_param_value(char *param, char *value, char *msg, size_t size) {

	struct core_param *p = core_params;
	while (p) {
		if (!strcmp(p->name, param))
			break;
		p = p->next;
	}

	if (!p) {
		snprintf(msg, size, "No such parameter %s", param);
		return POM_ERR;
	}

	if (p->can_change && (*p->can_change) (p->value, msg, size) == POM_ERR)
		return POM_ERR;

	if (ptype_parse_val(p->value, value) == POM_ERR) {
		snprintf(msg, size, "Unable to parse %s for parameter %s", value, param);
		return POM_ERR;
	}

	return POM_OK;
}

int core_param_unregister_all() {

	while (core_params) {
		struct core_param *p = core_params;
		free(p->name);
		free(p->defval);
		free(p->descr);
		core_params = core_params->next;
		free(p);
	}
	return POM_OK;
}
