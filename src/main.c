/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2008 Guy Martin <gmsoft@tuxicoman.be>
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
#include "version.h"
#include "conf.h"
#include "conntrack.h"
#include "helper.h"
#include "input.h"
#include "mgmtsrv.h"
#include "ptype.h"

#ifdef USE_XMLRPC
#include "xmlrpcsrv.h"
#endif

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

#define INPUTSIG SIGUSR1

struct conf *main_config;

struct core_param *core_params;
uint32_t core_params_serial;

struct ringbuffer *rbuf;

static pthread_mutex_t reader_mutex = PTHREAD_MUTEX_INITIALIZER; ///< Mutex used to lock the reader thread if changes are made or modules are loaded/unloaded
static pthread_t input_thread;

static int finish = 0;

static struct timeval now; ///< Used to get the current time from the input perspective

void signal_handler(int signal) {
	
	pom_log("Received signal. Finishing ... !");
	finish = 1;
	if (rbuf && rbuf->state != rb_state_closed)
		rbuf->state = rb_state_stopping;

}

void input_signal_handler(int signal) {

	if (!rbuf || !rbuf->i)
		return;

	pom_log(POM_LOG_TSHOOT "Interrupting input syscall ...");

	input_interrupt(rbuf->i);

}

void print_usage() {

	printf(	"Usage : packet-o-matic [options]\n"
		"\n"
		"Options :\n"
		" -c, --config=FILE          specify configuration file to use (default pom.xml.conf)\n"
		" -b, --background           run in the background as a daemon\n"
		" -e, --empty-config         start with an empty config\n"
		" -h, --help                 display the help\n"
		"     --no-cli               disable the CLI console\n"
		" -p, --port=PORT            specify the CLI console port (default 4655)\n"
		" -w, --password=PASS        specify a password to enter the CLI console\n"
		" -d, --debug-level=LEVEL    specify the debug level for the console <0-5> (default 3)\n"
#ifdef USE_XMLRPC
		" -X  --enable-xmlrpc        enable the XML-RPC interface\n"
		" -P, --xmlrpc-port=PORT     specify the XML-RPC port (default 8080)\n"
		" -W, --xmlrpc-password=PASS specify the password for XML-RPC calls\n"
#endif
		"\n"
		);
	

}


int help_load_modules(char *dir) {


	DIR *d;
	d = opendir(dir);
	if (!d) 
		return 0;

	struct dirent *dp;
	char type[NAME_MAX];

	int modules_count = 0;

	while ((dp = readdir(d))) {

		if (sscanf(dp->d_name, "input_%s", type) == 1) {
			while (strlen(type) > 0) {
				if (type[strlen(type) - 1] == '.') {
					type[strlen(type) - 1] = 0;
					break;
				}
				type[strlen(type) - 1] = 0;
			}
			if (input_register(type) != POM_ERR)
				modules_count++;
		}

		if (sscanf(dp->d_name, "target_%s", type) == 1) {
			while (strlen(type) > 0) {
				if (type[strlen(type) - 1] == '.') {
					type[strlen(type) - 1] = 0;
					break;
				}
				type[strlen(type) - 1] = 0;
			}
			if (target_register(type) != POM_ERR)
				modules_count++;
		}

		if (sscanf(dp->d_name, "match_%s", type) == 1) {
			while (strlen(type) > 0) {
				if (type[strlen(type) - 1] == '.') {
					type[strlen(type) - 1] = 0;
					break;
				}
				type[strlen(type) - 1] = 0;
			}
			if (match_register(type) != POM_ERR)
				modules_count++;
		}
	}

	closedir(d);

	return modules_count;

}

void print_help() {

	print_usage();

	int modules_count = 0;

	char *path = getenv("LD_LIBRARY_PATH");

	if (!path)
		modules_count = help_load_modules(LIBDIR);
	else {
		char *my_path = malloc(strlen(path) + 1);
		strcpy(my_path, path);
		
		char *str, *token, *saveptr = NULL;
		for (str = my_path; ; str = NULL) {
			token = strtok_r(str, ":", &saveptr);
			if (!token)
				break;
			modules_count += help_load_modules(token);
		}
		free(my_path);
	}

	if (!modules_count) {
		printf("No module found.\r\n");
		return;
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

#ifdef USE_XMLRPC
void *xmlrpcsrv_thread_func(void *params) {

	while (!finish) {
		xmlrpcsrv_process();
	}
	return NULL;
}
#endif

int start_input(struct ringbuffer *r) {


	if (r->state != rb_state_closed) {
		pom_log(POM_LOG_WARN "Input already started or being started");
		return POM_ERR;
	}

	if (pthread_mutex_lock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording");
		return POM_ERR;
	}

	r->state = rb_state_opening;

	int fd = input_open(main_config->input);

	if (fd == POM_ERR) {
		pom_log(POM_LOG_ERR "Error while opening input");
		r->state = rb_state_closed;
		pthread_mutex_unlock(&r->mutex);
		return POM_ERR;
	}

	r->fd = fd;

	if (ringbuffer_alloc(r, main_config->input) == POM_ERR) {
		pom_log(POM_LOG_ERR "Error while allocating the ringbuffer");
		input_close(r->i);
		r->state = rb_state_closed;
		pthread_mutex_unlock(&r->mutex);
		return POM_ERR;
	}

	r->state = rb_state_open;


	if (pthread_create(&input_thread, NULL, input_thread_func, (void*)r)) {
		pom_log(POM_LOG_ERR "Error when creating the input thread. Abording");
		input_close(r->i);
		r->state = rb_state_closed;
		return POM_ERR;
	}
	
	if (pthread_mutex_unlock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording");
		input_close(r->i);
		r->state = rb_state_closed;
		return POM_ERR;
	}
	return POM_OK;

}

int stop_input(struct ringbuffer *r) {

	if (r->state != rb_state_open && r->state != rb_state_stopping) {
		pom_log(POM_LOG_WARN "Input not yet started");
		return POM_ERR;
	}

	if (pthread_mutex_lock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording");
		return POM_ERR;
	}

	r->state = rb_state_stopping;

	if (pthread_mutex_unlock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording");
		return POM_ERR;
	}

	// interrupt current read()
	pom_log(POM_LOG_TSHOOT "Sending signal to interrupt the input thread");
	pthread_kill(input_thread, INPUTSIG);

	pthread_join(input_thread, NULL);

	return POM_OK;

}

void *input_thread_func(void *params) {

	struct ringbuffer *r = params;


	if (pthread_mutex_lock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording");
		finish = 1;
		return NULL;
	}

	// allow INPUTSIG to interrupt syscall
	static sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, INPUTSIG);
	pthread_sigmask(SIG_UNBLOCK, &sigmask, NULL);
	siginterrupt(INPUTSIG, 1);

	// set handler input_signal_handler() for the INPUTSIG
	struct sigaction mysigaction;
	sigemptyset(&mysigaction.sa_mask);
	mysigaction.sa_flags = 0;
	mysigaction.sa_handler = input_signal_handler;
	sigaction(INPUTSIG, &mysigaction, NULL);

	pom_log(POM_LOG_DEBUG "Input thead started");

	while (r->state == rb_state_open) {

		if (pthread_mutex_unlock(&r->mutex)) {
			pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording");
			finish = 1;
			return NULL;
		}

		if (r->state != rb_state_open)
			break;

		if (input_read(r->i, r->buffer[r->write_pos]) == POM_ERR) {
			pom_log(POM_LOG_ERR "Error while reading from input");
			// We need to aquire the lock
			pthread_mutex_lock(&r->mutex);

			// Need to update serial because input stopped
			main_config->input_serial++;

			r->state = rb_state_closing;

			struct ptype* param_quit_on_input_error =  core_get_param_value("quit_on_input_error");
			if (PTYPE_BOOL_GETVAL(param_quit_on_input_error)) {
				pom_log("Terminating application. One moment ...");	
				finish = 1;
			}
			
			break;
		}

		if (pthread_mutex_lock(&r->mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording");
			finish = 1;
			return NULL;
		}

		if (r->buffer[r->write_pos]->len == 0)
			continue;

		if (!r->usage) {
			pthread_cond_signal(&r->underrun_cond);
		}

		r->total_packets++;
		r->usage++;

		while (r->usage >= PTYPE_UINT32_GETVAL(r->size) - 1) {
			if (r->ic.is_live) {
				//pom_log(POM_LOG_TSHOOT "Buffer overflow (%u). droping packet", r->usage);
				r->write_pos--;
				r->dropped_packets++;
				r->usage--;
				break;
			} else {
				//pom_log(POM_LOG_TSHOOT "Buffer is full. Waiting");
				if(pthread_cond_wait(&r->overflow_cond, &r->mutex)) {
					pom_log(POM_LOG_ERR "Failed to wait for buffer to empty out");
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

	// If we are stopping, we'll set running = 1 to the input
	// this way autosave config will know it was started
	if (finish)
		r->i->running = 1;

	while (r->usage) {
		pthread_cond_signal(&r->underrun_cond);
		pthread_mutex_unlock(&r->mutex);
		pom_log(POM_LOG_TSHOOT "Waiting for ringbuffer to be empty");
		usleep(50000);
		pthread_mutex_lock(&r->mutex);
		
	}

	ringbuffer_cleanup(r);

	if (pthread_mutex_unlock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording");
		finish = 1;
		return NULL;
	}
	r->state = rb_state_closed;

	pom_log(POM_LOG_DEBUG "Input thread stopped");

	return NULL;
}


int main(int argc, char *argv[]) {

#if defined DEBUG && defined HAVE_MCHECK_H
	mtrace();
#endif

	core_params = NULL;

	console_debug_level = *POM_LOG_INFO;
	console_output = 1;

	char *cfgfile = "pom.xml.conf";
	int empty_config = 0;
	int disable_mgmtsrv = 0;
	char *cli_port = "4655";
#ifdef USE_XMLRPC
	int disable_xmlrpcsrv = 1;
	char *xmlrpc_port = "8080";
#endif

	int c;

	while (1) {
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "background", 0, 0, 'b' },
			{ "config", 1, 0, 'c'},
			{ "empty-config", 0, 0, 'e'},
			{ "port", 1, 0, 'p'},
			{ "password", 1, 0, 'w'},
			{ "no-cli", 0, 0, 1},
			{ "debug-level", 1, 0, 'd'},
#ifdef USE_XMLRPC
			{ "enable-xmlrpc", 0, 0, 'X'},
			{ "xmlrpc-port", 1, 0, 'P'},
			{ "xmlrcp-password", 1, 0, 'W'},
#endif
			{ 0, 0, 0, 0}
		};

		char *args = "hbc:ep:w:d:";
#ifdef USE_XMLRPC
		args = "hbc:ep:w:d:XP:W:";
#endif

		c = getopt_long(argc, argv, args, long_options, NULL);

		if (c == -1)
			break;

		switch(c) {
			case 1:
				disable_mgmtsrv = 1;
				pom_log("Not starting CLI console because of --no-cli flag");
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
				pom_log_cleanup();
				return 0;
			case 'c':
				cfgfile = optarg;
				pom_log("Config file is %s", optarg);
				break;
			case 'b': {
				pid_t pid = fork();
				if (pid == -1)
					pom_log("Error while forking, can't go in background mode");
				else if (pid != 0)
					return 0;
				console_output = 0;
				break;
			}
				
			case 'e':
				empty_config = 1;
				pom_log("Starting with an empty configuration");
				break;
			case 'p':
				cli_port = optarg;
				pom_log("Using port %s for CLI console", cli_port);
				break;
			case 'w':
				mgmtsrv_set_password(optarg);
				pom_log("CLI is password protected");
				break;
			case 'd':
				if (sscanf(optarg, "%u", &console_debug_level) == 1) {
					printf("Debug level set to %u\n", console_debug_level);
					break;
				} else {
					printf("Invalid debug level \"%s\"\n", optarg);
				}
#ifdef USE_XMLRPC
			case 'X':
				disable_xmlrpcsrv = 0;
				break;
			case 'P':
				xmlrpc_port = optarg;
				pom_log("Using port %s for XML-RPC interface",xmlrpc_port);
				break;
			case 'W':
				xmlrpcsrv_set_password(optarg);
				pom_log("XML-RPC interface is password protected");
				break;
#endif
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
	expectation_init();


	struct ptype *param_autosave_on_exit = ptype_alloc("bool", NULL);
	struct ptype *param_quit_on_input_error = ptype_alloc("bool", NULL);
	if (!param_autosave_on_exit || !param_quit_on_input_error) {
		// This is the very first module to be loaded
		pom_log(POM_LOG_ERR "Cannot allocate ptype bool. Abording");
		pom_log(POM_LOG_ERR "Did you set LD_LIBRARY_PATH correctly ?\r\n");
		return -1;
	}
	core_register_param("autosave_config_on_exit", "yes", param_autosave_on_exit, "Automatically save the configuration when exiting", NULL);
	core_register_param("quit_on_input_error", "no", param_quit_on_input_error, "Quit when there is an error on the input", NULL);


	rbuf = malloc(sizeof(struct ringbuffer));

	if (ringbuffer_init(rbuf) == POM_ERR) {
		goto finish;
	}

	// Install the signal handler
	struct sigaction mysigaction;
	sigemptyset(&mysigaction.sa_mask);
	mysigaction.sa_flags = 0;
	mysigaction.sa_handler = signal_handler;
	sigaction(SIGINT, &mysigaction, NULL);
	sigaction(SIGHUP, &mysigaction, NULL);

	// Ignore INPUTSIG in this thread and subsequent ones
	static sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, INPUTSIG);
	pthread_sigmask(SIG_BLOCK, &sigmask, NULL);

	main_config = config_alloc();

	pthread_t mgmtsrv_thread;
	if (!disable_mgmtsrv) {
		if (mgmtsrv_init(cli_port) == POM_ERR) {
			pom_log(POM_LOG_ERR "Error when initializing the management console. Abording");
			goto err;
		}
		if (pthread_create(&mgmtsrv_thread, NULL, mgmtsrv_thread_func, NULL)) {
			pom_log(POM_LOG_ERR "Error when creating the management console thread. Abording");
			goto err;
		}
	}

#ifdef USE_XMLRPC
	pthread_t xmlrpcsrv_thread;
	if (!disable_xmlrpcsrv) {
		if (xmlrpcsrv_init(xmlrpc_port) == POM_ERR) {
			pom_log(POM_LOG_ERR "Error while initializing the XML-RPC interface. Abording");
			goto err;
		}
		if (pthread_create(&xmlrpcsrv_thread, NULL, xmlrpcsrv_thread_func, NULL)) {
			pom_log(POM_LOG_ERR "Error when creating the XML-RPC thread. Abording");
			goto err;
		}
	}
#endif

	if (empty_config) {
		strncpy(main_config->filename, cfgfile, NAME_MAX);
	} else {
		if (config_parse(main_config, cfgfile) == POM_ERR) {
			pom_log(POM_LOG_ERR "Error while parsing config");
			goto err;
		}
	}

	rbuf->i = main_config->input;

	pom_log("packet-o-matic " POM_VERSION " started");

	if (pthread_mutex_lock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording");
		goto finish;
	}

	// wait for at least one packet to be available
	while (!rbuf->usage) {
		if (finish) {
			pthread_mutex_unlock(&rbuf->mutex);
			goto finish;
		}
		//pom_log(POM_LOG_TSHOOT "Buffer empty (%u). Waiting", rbuf->usage);
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
				pom_log(POM_LOG_ERR "Error occured while waiting for next frame to be available");
				pthread_mutex_unlock(&rbuf->mutex);
				goto finish;

		}
	}


	while (1) {
		
		if (pthread_mutex_unlock(&rbuf->mutex)) {
			pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Abording");
			goto finish;
		}
	
		if (rbuf->ic.is_live)
			gettimeofday(&now, NULL);
		else {
			memcpy(&now, &rbuf->buffer[rbuf->read_pos]->tv, sizeof(struct timeval));
			now.tv_usec += 1;
		}

		if (pthread_mutex_lock(&reader_mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the reader mutex. Abording");
			goto finish;
		}
	
		if (rbuf->buffer[rbuf->read_pos]->len > 0) { // Need to queue that in the buffer
			timers_process(); // This is not real-time timers but we don't really need it
			do_rules(rbuf->buffer[rbuf->read_pos], main_config->rules, &main_config->rules_lock);
			helper_lock(0);
			helper_process_queue(main_config->rules, &main_config->rules_lock); // Process frames that needed some help
			helper_unlock();
		}


		if (pthread_mutex_unlock(&reader_mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the reader mutex. Abording");
			goto finish;
		}


		if (pthread_mutex_lock(&rbuf->mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Abording");
			goto finish;
		}
		rbuf->usage--;
		if (!rbuf->ic.is_live && rbuf->usage <= PTYPE_UINT32_GETVAL(rbuf->size) - 1)
			pthread_cond_signal(&rbuf->overflow_cond);

		rbuf->read_pos++;
		if (rbuf->read_pos >= PTYPE_UINT32_GETVAL(rbuf->size))
			rbuf->read_pos = 0;


		while (!rbuf->usage) {
			if (rbuf->state == rb_state_stopping || rbuf->state == rb_state_closed) {
				// Process remaining queued frames
				conntrack_close_connections(main_config->rules, &main_config->rules_lock);
				expectation_cleanup_all();
			}

			if (finish && rbuf->state == rb_state_closed) {
				pthread_mutex_unlock(&rbuf->mutex);
				goto finish;
			}

			struct timeval tv;
			gettimeofday(&tv, NULL);
			struct timespec tp;
			tp.tv_sec = tv.tv_sec + 3;
			tp.tv_nsec = tv.tv_usec * 1000;
			switch (pthread_cond_timedwait(&rbuf->underrun_cond, &rbuf->mutex, &tp)) {
				case ETIMEDOUT:
					//pom_log(POM_LOG_TSHOOT "Timeout occured while waiting for next frame to be available");
				case 0:
					break;
				default:
					pom_log(POM_LOG_ERR "Error occured while waiting for next frame to be available");
					pthread_mutex_unlock(&rbuf->mutex);
					goto finish;

			}
		}



	}

finish:
	finish = 1;

	// Save the config before changing anything
	if (PTYPE_BOOL_GETVAL(param_autosave_on_exit)) {
		pom_log("Autosaving configuration to %s", main_config->filename);
		config_write(main_config, main_config->filename);
	}

	if (rbuf->i)
		stop_input(rbuf);

	if (!disable_mgmtsrv)
		pthread_join(mgmtsrv_thread, NULL);

#ifdef USE_XMLRPC
	if (!disable_xmlrpcsrv)
		pthread_join(xmlrpcsrv_thread, NULL);
#endif

	pom_log("Total packets read : %lu, dropped %lu (%.2f%%)", rbuf->total_packets, rbuf->dropped_packets, 100.0 / rbuf->total_packets * rbuf->dropped_packets);

	// Process remaining queued frames
	conntrack_close_connections(main_config->rules, &main_config->rules_lock);

	expectation_cleanup_all();

err:

	if (!disable_mgmtsrv)
		mgmtsrv_cleanup();
#ifdef USE_XMLRPC	
	if (!disable_xmlrpcsrv)
		xmlrpcsrv_cleanup();
#endif
	config_cleanup(main_config);

	helper_unregister_all();
	helper_cleanup();

	conntrack_cleanup();
	timers_cleanup();
	target_cleanup();

	target_unregister_all();
	
	match_unregister_all();
	match_cleanup();

	conntrack_unregister_all();
	input_unregister_all();

	// Layers need to be cleaned up after the match
	layer_cleanup();

	ringbuffer_deinit(rbuf);
	free(rbuf);
	ptype_cleanup(param_autosave_on_exit);
	ptype_cleanup(param_quit_on_input_error);
	core_param_unregister_all();

	ptype_unregister_all();

	pom_log_cleanup();

	return 0;
}

int ringbuffer_init(struct ringbuffer *r) {
	memset(r, 0, sizeof(struct ringbuffer));
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

	ptype_cleanup(r->size);
	return POM_OK;
}

int ringbuffer_alloc(struct ringbuffer *r, struct input *in) {

	r->i = in;

	if (input_getcaps(r->i, &r->ic) == POM_ERR) {
		pom_log(POM_LOG_ERR "Error while getting input capabilities");
		return POM_ERR;
	}

	// Initialize the ring buffer
	pom_log(POM_LOG_DEBUG "Using %u buffers of %u bytes", PTYPE_UINT32_GETVAL(r->size), r->ic.snaplen);

	r->buffer = malloc(sizeof(struct frame*) * PTYPE_UINT32_GETVAL(r->size));

	int i;
	for (i = 0; i < PTYPE_UINT32_GETVAL(r->size); i++) {
		r->buffer[i] = malloc(sizeof(struct frame));
		memset(r->buffer[i], 0, sizeof(struct frame));
		r->buffer[i]->input = in;
		frame_alloc_aligned_buff(r->buffer[i], r->ic.snaplen);
		r->buffer[i]->input = main_config->input;

	}
	r->read_pos = PTYPE_UINT32_GETVAL(r->size) - 1;
	r->write_pos = 0;

	return POM_OK;

}

int ringbuffer_cleanup(struct ringbuffer *r) {

	int i;

	for (i = 0; i < PTYPE_UINT32_GETVAL(r->size); i++) {
		free(r->buffer[i]->buff_base);
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

	pom_log("Stopping application ...");
	finish = 1;
	if (rbuf->state != rb_state_closed)
		rbuf->state = rb_state_stopping;
	return POM_OK;
}

int core_register_param(char *name, char *defval, struct ptype *value, char *descr, int (*param_can_change) (struct ptype *value, char *msg, size_t size)) {

	struct core_param *p = malloc(sizeof(struct core_param));
	memset(p, 0, sizeof(struct core_param));

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

	core_params_serial++;

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

int main_config_rules_lock(int write) {

	int result = 0;
	if (write) {
		result = pthread_rwlock_wrlock(&main_config->rules_lock);
	} else {
		result = pthread_rwlock_rdlock(&main_config->rules_lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking the rule lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

int main_config_rules_unlock() {

	if (pthread_rwlock_unlock(&main_config->rules_lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the rule lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

