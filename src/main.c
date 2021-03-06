/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2007-2009 Guy Martin <gmsoft@tuxicoman.be>
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
#include "datastore.h"

#ifdef USE_XMLRPC
#include "xmlrpcsrv.h"
#endif

#ifdef USE_NETSNMP
#include "snmpagent.h"
#endif

#include "main.h"
#include "core_param.h"

#include "ptype_bool.h"
#include "ptype_uint32.h"

#if defined DEBUG && defined HAVE_MCHECK_H
#include <mcheck.h>
#endif

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>

#include <time.h>
#ifdef TIME_WITH_SYS_TIME
#include <sys/time.h>
#endif

#ifdef HAVE_EXECINFO_H
#include <execinfo.h>
#endif

#include <libxml/xmlerror.h>

#define INPUTSIG SIGUSR1

struct conf *main_config;

struct ringbuffer *rbuf;

static pthread_mutex_t reader_mutex = PTHREAD_MUTEX_INITIALIZER; ///< Mutex used to lock the reader thread if changes are made or modules are loaded/unloaded
static pthread_t input_thread;

static int finish = 0, sighup = 0;

static struct perf_class *core_perf_class = NULL;
static struct perf_instance *core_perf_instance = NULL;
struct perf_item *core_perf_uptime = NULL;

void signal_handler(int signal) {

	switch (signal) {

		case SIGHUP:
			sighup = 1;
			break;

		case INPUTSIG: // SIGUSR1
			
			if (!rbuf || !rbuf->i)
				return;
			input_interrupt(rbuf->i);
			break;

		case SIGQUIT:
		case SIGBUS:
		case SIGSEGV: {
			printf("*CRASH* :-(\n");
			printf("Awww packet-o-matic crashed. This should not be happening !\n");
			printf("Please report this to " PACKAGE_BUGREPORT " to have this fixed.\n");
#ifdef HAVE_EXECINFO_H
			int nptrs;
			char **strings;
			const int max_stack_size = 100;
			void *buff[max_stack_size];
			nptrs = backtrace(buff, max_stack_size);

			strings = backtrace_symbols(buff, nptrs);
			if (!strings) {
				printf("Unable to display a backtrace, no string representation of the stack available.\n");
				exit(EXIT_FAILURE);
			} 

			printf("Provide the following output while reporting the crash :\n");
			printf("-------------------------- CUT HERE --------------------------\n");
			int i;
			for (i = 0; i < nptrs; i++)
				printf("%u: %s\n", nptrs - i, strings[i]);
			printf("-------------------------- CUT HERE --------------------------\n");
			free(strings);

#else
			printf("No backtrace available.\n");
#endif

			// Resend the signal with the default handler
			struct sigaction mysigaction;
			sigemptyset(&mysigaction.sa_mask);
			mysigaction.sa_flags = 0;
			mysigaction.sa_handler = SIG_DFL;
			sigaction(signal, &mysigaction, NULL);
			raise(signal);

			abort(); // Just in case 

			break;
		}

		default: // Should be only SIGINT
			// Use printf and not pom_log
			printf("Received signal. Finishing ... !\n");
			finish = 1;
			if (rbuf && rbuf->state != rb_state_closed)
				rbuf->state = rb_state_stopping;
			break;
	}

}

void print_usage() {

	printf(	"Usage : packet-o-matic [options]\n"
		"\n"
		"Options :\n"
		" -c, --config=FILE          specify configuration file to use (default pom.xml.conf)\n"
		" -b, --background           run in the background as a daemon\n"
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
#ifdef USE_NETSNMP
		" -S, --enable-snmpagent     enable the Net-SNMP sub agent\n"
#endif
		"     --pid-file             specify the file where to write the PID\n"
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

#ifdef USE_NETSNMP
void *snmpagent_thread_func(void *params) {

	while (!finish) {
		snmpagent_process();
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
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Aborting");
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
		pom_log(POM_LOG_ERR "Error when creating the input thread. Aborting");
		input_close(r->i);
		r->state = rb_state_closed;
		return POM_ERR;
	}
	
	if (pthread_mutex_unlock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Aborting");
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
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Aborting");
		return POM_ERR;
	}

	r->state = rb_state_stopping;

	if (pthread_mutex_unlock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Aborting");
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
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Aborting");
		finish = 1;
		return NULL;
	}

	// allow INPUTSIG to interrupt syscall
	static sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, INPUTSIG);
	pthread_sigmask(SIG_UNBLOCK, &sigmask, NULL);
	siginterrupt(INPUTSIG, 1);

	// set handler signal_handler() for the INPUTSIG
	struct sigaction mysigaction;
	sigemptyset(&mysigaction.sa_mask);
	mysigaction.sa_flags = 0;
	mysigaction.sa_handler = signal_handler;
	sigaction(INPUTSIG, &mysigaction, NULL);

	pom_log(POM_LOG_DEBUG "Input thead started");

	while (r->state == rb_state_open) {

		if (pthread_mutex_unlock(&r->mutex)) {
			pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Aborting");
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

		if (!r->i->running) { // Input was closed
			main_config->input_serial++;
			break;
		}

		if (pthread_mutex_lock(&r->mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Aborting");
			finish = 1;
			return NULL;
		}

		if (r->buffer[r->write_pos]->len == 0)
			continue;

		if (!r->usage) {
			pthread_cond_signal(&r->underrun_cond);
		}

		perf_item_val_inc(r->perf_total_packets, 1);
		r->usage++;

		int overflowed = 0;
		while (r->usage >= PTYPE_UINT32_GETVAL(r->size) - 1) {
			if (r->ic.is_live) {
				//pom_log(POM_LOG_TSHOOT "Buffer overflow (%u). droping packet", r->usage);
				overflowed = 1;
				r->write_pos--;
				perf_item_val_inc(r->perf_dropped_packets, 1);
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
		if (overflowed)
			perf_item_val_inc(r->perf_overflow, 1);

		r->write_pos++;
		if (r->write_pos >= PTYPE_UINT32_GETVAL(r->size))
			r->write_pos = 0;


	}

	if (r->i->running)
		input_close(r->i);

	// If we are stopping, we'll set running = 1 to the input
	// this way autosave config will know it was started
	if (finish)
		r->i->running = 1;

	while (r->usage) {
		pthread_cond_signal(&r->underrun_cond);
		pthread_mutex_unlock(&r->mutex);
		//pom_log(POM_LOG_TSHOOT "Waiting for ringbuffer to be empty");
		usleep(50000);
		pthread_mutex_lock(&r->mutex);
		
	}

	ringbuffer_cleanup(r);

	if (pthread_mutex_unlock(&r->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Aborting");
		finish = 1;
		return NULL;
	}
	r->state = rb_state_closed;

	pom_log(POM_LOG_DEBUG "Input thread stopped");

	pthread_detach(input_thread);

	return NULL;
}


int main(int argc, char *argv[]) {

#if defined DEBUG && defined HAVE_MCHECK_H
	mtrace();
#endif

	console_debug_level = *POM_LOG_INFO;
	console_output = 1;

	char *cfgfile = "pom.xml.conf";
	int disable_mgmtsrv = 0;
	char *cli_port = "4655";
#ifdef USE_XMLRPC
	int disable_xmlrpcsrv = 1;
	char *xmlrpc_port = "8080";
#endif
#ifdef USE_NETSNMP
	int disable_snmpagent = 1;
#endif
	char *pidfile = NULL;

	int c;

	while (1) {
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "background", 0, 0, 'b' },
			{ "config", 1, 0, 'c'},
			{ "port", 1, 0, 'p'},
			{ "password", 1, 0, 'w'},
			{ "no-cli", 0, 0, 1},
			{ "debug-level", 1, 0, 'd'},
#ifdef USE_XMLRPC
			{ "enable-xmlrpc", 0, 0, 'X'},
			{ "xmlrpc-port", 1, 0, 'P'},
			{ "xmlrcp-password", 1, 0, 'W'},
#endif
#ifdef USE_NETSNMP
			{ "enable-snmpagent", 0, 0, 'S'},
#endif
			{ "pid-file", 1, 0, 2},
			{ 0, 0, 0, 0}
		};

		char *args = "hbc:ep:w:d:" 
#ifdef USE_XMLRPC
		"XP:W:" 
#endif

#ifdef USE_NETSNMP
		"S"
#endif
		;

		c = getopt_long(argc, argv, args, long_options, NULL);

		if (c == -1)
			break;

		switch(c) {
			case 1:
				disable_mgmtsrv = 1;
				pom_log("Not starting CLI console because of --no-cli flag");
				break;
			case 2:
				pidfile = optarg;
				pom_log("PID file is %s", optarg);
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
				perf_cleanup();
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
					if (console_debug_level)
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
#ifdef USE_NETSNMP
			case 'S':
				disable_snmpagent = 0;
				break;
#endif
			case '?':
			default:
				print_usage();
				return 1;

		}
	}

	if (optind < argc) {
		print_usage();
		return 1;
	}

	// Write to the pidfile
	if (pidfile) {
		FILE* pid_fd = fopen(pidfile, "w");
		if (!pid_fd) {
			pom_log(POM_LOG_ERR "Unable to open PID file %s");
			return -1;
		}
		fprintf(pid_fd, "%u\n", (unsigned) getpid());
		fclose(pid_fd);
	}


	// Set libxml2 error handler
	xmlSetGenericErrorFunc(NULL, libxml_error_handler);


	// Init the stuff
	uid_init();
	ptype_init();
	layer_init();
	match_init();
	conntrack_init();
	helper_init();
	target_init();
	rules_init();
	expectation_init();

	core_perf_class = perf_register_class("core");
	core_perf_instance = perf_register_instance(core_perf_class, NULL);
	core_perf_uptime = perf_add_item(core_perf_instance, "uptime", perf_item_type_uptime, "UpTime of packet-o-matic");
	perf_item_val_reset(core_perf_uptime);


	struct ptype *param_autosave_on_exit = ptype_alloc("bool", NULL);
	struct ptype *param_quit_on_input_error = ptype_alloc("bool", NULL);
	struct ptype *param_reset_counters_on_restart = ptype_alloc("bool", NULL);
	if (!param_autosave_on_exit || !param_quit_on_input_error || !param_reset_counters_on_restart) {
		// This is the very first module to be loaded
		pom_log(POM_LOG_ERR "Cannot allocate ptype bool. Aborting");
		pom_log(POM_LOG_ERR "Did you set LD_LIBRARY_PATH correctly ?\r\n");
		return -1;
	}
	core_register_param("autosave_config_on_exit", "yes", param_autosave_on_exit, "Automatically save the configuration when exiting", NULL);
	core_register_param("quit_on_input_error", "no", param_quit_on_input_error, "Quit when there is an error on the input", NULL);
	core_register_param("reset_counters_on_item_restart", "yes", param_reset_counters_on_restart, "Reset counters when restarting/reenabling an item", NULL);


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
	sigaction(SIGQUIT, &mysigaction, NULL);
	sigaction(SIGBUS, &mysigaction, NULL);
	sigaction(SIGSEGV, &mysigaction, NULL);

	// Ignore INPUTSIG in this thread and subsequent ones
	static sigset_t sigmask;
	sigemptyset(&sigmask);
	sigaddset(&sigmask, INPUTSIG);
	pthread_sigmask(SIG_BLOCK, &sigmask, NULL);

	main_config = config_alloc();

	pthread_t mgmtsrv_thread;
	if (!disable_mgmtsrv) {
		if (mgmtsrv_init(cli_port) == POM_ERR) {
			pom_log(POM_LOG_ERR "Error when initializing the management console. Aborting");
			goto err;
		}
		if (pthread_create(&mgmtsrv_thread, NULL, mgmtsrv_thread_func, NULL)) {
			pom_log(POM_LOG_ERR "Error when creating the management console thread. Aborting");
			goto err;
		}
	}

#ifdef USE_XMLRPC
	pthread_t xmlrpcsrv_thread;
	if (!disable_xmlrpcsrv) {
		if (xmlrpcsrv_init(xmlrpc_port) == POM_ERR) {
			pom_log(POM_LOG_ERR "Error while initializing the XML-RPC interface. Aborting");
			goto err;
		}
		if (pthread_create(&xmlrpcsrv_thread, NULL, xmlrpcsrv_thread_func, NULL)) {
			pom_log(POM_LOG_ERR "Error when creating the XML-RPC thread. Aborting");
			goto err;
		}
	}
#endif

#ifdef USE_NETSNMP
	pthread_t snmpagent_thread;
	if (!disable_snmpagent) {
		if (snmpagent_init() == POM_ERR) {
			pom_log(POM_LOG_ERR "Error while initializing the SNMP interface. Aborting");
			goto err;
		}
		if (pthread_create(&snmpagent_thread, NULL, snmpagent_thread_func, NULL)) {
			pom_log(POM_LOG_ERR "Error when creating the SNMP thread. Aborting");
			goto err;
		}
	}
#endif

	// Check if the config file exists
	struct stat st;
	if (stat(cfgfile, &st)) {
		char errbuff[256];
		memset(errbuff, 0, sizeof(errbuff));
		strerror_r(errno, errbuff, sizeof(errbuff));
		pom_log(POM_LOG_ERR "Could not open config file %s : %s", cfgfile, errbuff);
		pom_log(POM_LOG_WARN "Starting with and empty configuration");
		strncpy(main_config->filename, cfgfile, NAME_MAX);
	} else if (config_parse(main_config, cfgfile) == POM_ERR) {
		pom_log(POM_LOG_WARN "Starting with and empty configuration");
		config_cleanup(main_config);
		main_config = config_alloc();
		strncpy(main_config->filename, cfgfile, NAME_MAX);
		
	}

	rbuf->i = main_config->input;

	pom_log("packet-o-matic " POM_VERSION " started");

	if (pthread_mutex_lock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Aborting");
		goto finish;
	}

	// wait for at least one packet to be available
	while (!rbuf->usage) {
		if (finish) {
			pthread_mutex_unlock(&rbuf->mutex);
			goto finish;
		}

		if (sighup) { // Process SIGHUP actions
			main_process_sighup(main_config->rules, &main_config->rules_lock);
			sighup = 0;
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
			pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex. Aborting");
			goto finish;
		}
		struct timeval *now = get_current_time_p();
		if (rbuf->ic.is_live)
			gettimeofday(now, NULL);
		else {
			
			memcpy(now, &rbuf->buffer[rbuf->read_pos]->tv, sizeof(struct timeval));
			now->tv_usec += 1;
		}

		if (pthread_mutex_lock(&reader_mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the reader mutex. Aborting");
			goto finish;
		}
	
		if (rbuf->buffer[rbuf->read_pos]->len > 0) { // Need to queue that in the buffer
			timers_process(main_config->rules, &main_config->rules_lock); // Process events
			do_rules(rbuf->buffer[rbuf->read_pos], main_config->rules, &main_config->rules_lock);
			helper_process_queue(main_config->rules, &main_config->rules_lock); // Process frames that needed some help
		}

		if (sighup) { // Process SIGHUP actions
			main_process_sighup(main_config->rules, &main_config->rules_lock);
			sighup = 0;
		}


		if (pthread_mutex_unlock(&reader_mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the reader mutex. Aborting");
			goto finish;
		}


		if (pthread_mutex_lock(&rbuf->mutex)) {
			pom_log(POM_LOG_ERR "Error while locking the buffer mutex. Aborting");
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

			if (sighup) { // Process SIGHUP actions
				main_process_sighup(main_config->rules, &main_config->rules_lock);
				sighup = 0;
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

	if (rbuf->i && rbuf->state == rb_state_open)
		stop_input(rbuf);

	if (!disable_mgmtsrv) {
		pom_log(POM_LOG_INFO "Waiting for CLI mgmt thread to finish ...");
		pthread_join(mgmtsrv_thread, NULL);
	}

#ifdef USE_XMLRPC
	if (!disable_xmlrpcsrv) {
		pom_log(POM_LOG_INFO "Waiting for XML-RPC thread to finish ...");
		pthread_join(xmlrpcsrv_thread, NULL);
	}
#endif

#ifdef USE_NETSNMP
	if (!disable_snmpagent) {
		pom_log(POM_LOG_INFO "Waiting for NET-SNMP subagent thread to finish ...");
		pthread_join(snmpagent_thread, NULL);
	}
#endif

	pom_log("Total packets read : %lu, dropped %lu (%.2f%%)", perf_item_val_get_raw(rbuf->perf_total_packets), perf_item_val_get_raw(rbuf->perf_dropped_packets), 100.0 / perf_item_val_get_raw(rbuf->perf_total_packets) * perf_item_val_get_raw(rbuf->perf_dropped_packets));

	// Process remaining queued frames
	conntrack_close_connections(main_config->rules, &main_config->rules_lock);

	expectation_cleanup_all();

err:

	perf_unregister_instance(core_perf_class, core_perf_instance);

	if (!disable_mgmtsrv)
		mgmtsrv_cleanup();
#ifdef USE_XMLRPC	
	if (!disable_xmlrpcsrv)
		xmlrpcsrv_cleanup();
#endif

#ifdef USE_NETSNMP
	if (!disable_snmpagent)
		snmpagent_cleanup();
#endif
	config_cleanup(main_config);

	datastore_unregister_all();

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
	ptype_cleanup(param_reset_counters_on_restart);
	core_param_unregister_all();

	perf_cleanup();
	ptype_unregister_all();

	uid_cleanup();

	pom_log_cleanup();

	return 0;
}

int ringbuffer_init(struct ringbuffer *r) {
	memset(r, 0, sizeof(struct ringbuffer));
	pthread_mutex_init(&r->mutex, NULL);
	pthread_cond_init(&r->underrun_cond, NULL);
	pthread_cond_init(&r->overflow_cond, NULL);

	r->perf_dropped_packets = perf_add_item(core_perf_instance, "dropped_packets", perf_item_type_counter, "Total number of packets which went into the ring buffer");
	r->perf_total_packets = perf_add_item(core_perf_instance, "total_packets", perf_item_type_counter, "Total number of packets dropped in the ring buffer");
	r->perf_overflow = perf_add_item(core_perf_instance, "overflows", perf_item_type_counter, "Total number of time the buffer overflowed");

	r->size = ptype_alloc("uint32", "packets");
	if (!r->size)
		return POM_ERR;

	core_register_param("ringbuffer_size", "10000", r->size, "Number of packets to hold in the ringbuffer", ringbuffer_core_param_callback);

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
		r->buffer[i]->align_offset = r->ic.buff_align_offset;
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

int ringbuffer_core_param_callback(char *new_value, char *msg, size_t size) {


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

int halt() {

	pom_log("Stopping application ...");
	finish = 1;
	if (rbuf->state != rb_state_closed)
		rbuf->state = rb_state_stopping;
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

int main_config_datastores_lock(int write) {

	int result = 0;
	if (write) {
		result = pthread_rwlock_wrlock(&main_config->datastores_lock);
	} else {
		result = pthread_rwlock_rdlock(&main_config->datastores_lock);
	}

	if (result) {
		pom_log(POM_LOG_ERR "Error while locking the datastore lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

int main_config_datastores_unlock() {

	if (pthread_rwlock_unlock(&main_config->datastores_lock)) {
		pom_log(POM_LOG_ERR "Error while unlocking the datastore lock");
		abort();
		return POM_ERR;
	}

	return POM_OK;

}

void libxml_error_handler(void *ctx, const char *msg, ...) {

	va_list arg_list;
	char buff[2048];
	va_start(arg_list, msg);
	vsnprintf(buff, sizeof(buff) - 1, msg, arg_list);
	va_end(arg_list);

	pom_log_internal("libxml2", POM_LOG_TSHOOT "%s", buff);

	return;
}

int main_process_sighup(struct rule_list *r, pthread_rwlock_t *rule_lock) {

	if (pthread_rwlock_rdlock(rule_lock)) {
		pom_log(POM_LOG_ERR "Unable to lock the given rules");
		abort();
		return POM_ERR;
	}

	while (r) {
		struct target *t = r->target;
		while (t) {
			target_sighup(t);
			t = t->next;
		}
		r = r->next;
	}

	if (pthread_rwlock_unlock(rule_lock)) {
		pom_log(POM_LOG_ERR "Unable to lock the given rules");
		abort();
		return POM_ERR;
	}


	return POM_OK;
}
