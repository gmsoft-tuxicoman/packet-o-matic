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


#include "mgmtcmd_input.h"

#include <pthread.h>

#define MGMT_INPUT_COMMANDS_NUM 10

static struct mgmt_command mgmt_input_commands[MGMT_INPUT_COMMANDS_NUM] = {

	{
		.words = { "input", "show", NULL },
		.help = "Display informations about the input in use",
		.callback_func = mgmtcmd_input_show,
	},

	{
		.words = { "input", "start", NULL },
		.help = "Start the input",
		.callback_func = mgmtcmd_input_start,
	},

	{
		.words = { "input", "stop", NULL },
		.help = "Stop the input",
		.callback_func = mgmtcmd_input_stop,
	},

	{
		.words = { "input", "type", "set", NULL },
		.help = "Select another type of input",
		.callback_func = mgmtcmd_input_type_set,
		.completion = mgmtcmd_input_type_set_completion,
		.usage = "input type set <type>",
	},

	{
		.words = { "input", "mode", "set", NULL },
		.help = "Change the mode of the input",
		.callback_func = mgmtcmd_input_mode_set,
		.completion = mgmtcmd_input_mode_set_completion,
		.usage = "input mode set <mode>",
	},

	{
		.words = { "input", "parameter", "set", NULL },
		.help = "Change the value of an input parameter",
		.callback_func = mgmtcmd_input_parameter_set,
		.completion = mgmtcmd_input_parameter_set_completion,
		.usage = "input parameter set <parameter> <value>",
	},

	{
		.words = { "input", "parameter", "reset", NULL },
		.help = "Reset an input parameter to its default value",
		.callback_func = mgmtcmd_input_parameter_reset,
		.completion = mgmtcmd_input_parameter_set_completion,
		.usage = "input parameter reset <parameter>",
	},


	{
		.words = { "input", "load", NULL },
		.help = "Load an input module",
		.usage = "input load <input>",
		.callback_func = mgmtcmd_input_load,
		.completion = mgmtcmd_input_avail_completion,
	},

	{
		.words = { "input", "help", NULL },
		.help = "Get help for inputs",
		.usage = "input help [input]",
		.callback_func = mgmtcmd_input_help,
		.completion = mgmtcmd_input_avail_completion,
	},

	{
		.words = { "input", "unload", NULL },
		.help = "Unload an input module",
		.usage = "input unload <input>",
		.callback_func = mgmtcmd_input_unload,
		.completion = mgmtcmd_input_unload_completion,
	},
};

int mgmtcmd_input_register_all() {

	int i;


	for (i = 0; i < MGMT_INPUT_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_input_commands[i]);
	}

	return POM_OK;
}


int mgmtcmd_input_show(struct mgmt_connection *c, int argc, char *argv[]) {

	struct input* i = main_config->input;
	if (!i) {
		mgmtsrv_send(c, "No input configured yet. Use \"input type set <type>\" to choose an input\r\n");
		return POM_OK;
	}

	mgmtsrv_send(c, "Current input : ");
	mgmtsrv_send(c, input_get_name(i->type));
	mgmtsrv_send(c, ", mode ");
	mgmtsrv_send(c, i->mode->name);

	char pkts[32], bytes[32], uptime[64];
	perf_item_val_get_human(i->perf_pkts_in, pkts, sizeof(pkts) - 1);
	perf_item_val_get_human_1024(i->perf_bytes_in, bytes, sizeof(bytes) - 1);
	perf_item_val_get_human(i->perf_uptime, uptime, sizeof(uptime) - 1);
	mgmtsrv_send(c, " (%s packets, %s bytes, up %s)", pkts, bytes, uptime);

	if (i->running)
		mgmtsrv_send(c, " (running)\r\n");
	else
		mgmtsrv_send(c, "\r\n");
	
	struct input_param *p = i->mode->params;
	while (p) {
		char buff[256];
		memset(buff, 0, sizeof(buff));
		ptype_print_val(p->value, buff, sizeof(buff));
		mgmtsrv_send(c, "  %s = %s %s\r\n", p->name, buff, p->value->unit);
		p = p->next;
	}

	return POM_OK;
}

int mgmtcmd_input_start(struct mgmt_connection *c, int argc, char *argv[]) {


	if (rbuf->state != rb_state_closed) {
		mgmtsrv_send(c, "Input already started\r\n");
		return POM_OK;
	}

	if (!main_config->input) {
		mgmtsrv_send(c, "No input configured yet. Use \"input type set <type>\" to choose an input\r\n");
		return POM_OK;
	}

	if (start_input(rbuf) == POM_ERR)
		mgmtsrv_send(c, "Error while starting the input\r\n");

	main_config->input_serial++;

	return POM_OK;

}

int mgmtcmd_input_stop(struct mgmt_connection *c, int argc, char *argv[]) {


	if (rbuf->state == rb_state_closed) {
		mgmtsrv_send(c, "Input already stopped\r\n");
		return POM_OK;
	}

	if (stop_input(rbuf) == POM_ERR) {
		mgmtsrv_send(c, "Error while stopping the input\r\n");
		return POM_OK;
	}
	main_config->input_serial++;

	return POM_OK;

}

int mgmtcmd_input_type_set(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	if (pthread_mutex_lock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex");
		return POM_ERR;
	}

	if (rbuf->i && rbuf->i->running) {
		pthread_mutex_unlock(&rbuf->mutex);
		mgmtsrv_send(c, "Input is running. You need to stop it before doing any change\r\n");
		return POM_OK;
	}

	if (rbuf->i && !strcmp(argv[0], input_get_name(rbuf->i->type))) {
		pthread_mutex_unlock(&rbuf->mutex);
		mgmtsrv_send(c, "Input type is already %s\r\n", argv[0]);
		return POM_OK;
	}

	input_lock(1);
	struct input *i;
	int input_type = input_register(argv[0]);
	if (input_type == POM_ERR) {
		mgmtsrv_send(c, "Unable to register input %s\r\n", argv[0]);
		input_unlock();
		pthread_mutex_unlock(&rbuf->mutex);
		return POM_OK;
	}

	i = input_alloc(input_type);

	// we can unlock the inputs, we got a refcount
	input_unlock();

	if (!i) {
		mgmtsrv_send(c, "Unable to allocate input %s\r\n", argv[0]);
		pthread_mutex_unlock(&rbuf->mutex);
		return POM_OK;
	}

	if (rbuf->i)
		input_cleanup(rbuf->i);
	rbuf->i = i;
	main_config->input = i;

	main_config->input_serial++;

	if (pthread_mutex_unlock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex");
		return POM_ERR;
	}

	return POM_OK;
}

struct mgmt_command_arg* mgmtcmd_input_type_set_completion(int argc, char *argv[]) {

	if (argc != 3)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("input");
	return res;
}

int mgmtcmd_input_mode_set(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	if (pthread_mutex_lock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex");
		abort();
		return POM_ERR;
	} else 	if (!rbuf->i) {
		mgmtsrv_send(c, "No input configured yet. Use \"input type set <type>\" to choose an input\r\n");
	} else if (rbuf->i->running) {
		mgmtsrv_send(c, "Input is running. You need to stop it before doing any change\r\n");
	} else if (input_set_mode(rbuf->i, argv[0]) != POM_OK) {
		mgmtsrv_send(c, "No mode %s for this input\r\n", argv[0]);
	} else {
		main_config->input_serial++;
	}

	if (pthread_mutex_unlock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex");
	}

	return POM_OK;
}

struct mgmt_command_arg* mgmtcmd_input_mode_set_completion(int argc, char *argv[]) {
	
	if (argc != 3)
		return NULL;

	if (!rbuf->i || !inputs[rbuf->i->type])
		return NULL;

	struct mgmt_command_arg *res = NULL;

	struct input_mode *modes = inputs[rbuf->i->type]->modes;

	while (modes) {
		struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
		memset(item, 0, sizeof(struct mgmt_command_arg));
		item->word = malloc(strlen(modes->name) + 1);
		strcpy(item->word, modes->name);
	
		item->next = res;
		res = item;

		modes = modes->next;
	}

	return res;
}

int mgmtcmd_input_parameter_set(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;

	if (pthread_mutex_lock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex");
		return POM_ERR;
	}

	if (!rbuf->i) {
		pthread_mutex_unlock(&rbuf->mutex);
		mgmtsrv_send(c, "No input configured yet. Use \"input type set <type>\" to choose an input\r\n");
		return POM_OK;
	}

	if (rbuf->i->running) {
		pthread_mutex_unlock(&rbuf->mutex);
		mgmtsrv_send(c, "Input is running. You need to stop it before doing any change\r\n");
		return POM_OK;
	}

	struct input_param *p = rbuf->i->mode->params;

	while (p) {
		if (!strcmp(p->name, argv[0]))
			break;
		p = p->next;
	}

	if (!p) {
		pthread_mutex_unlock(&rbuf->mutex);
		mgmtsrv_send(c, "Parameter %s does not exists\r\n", argv[0]);
		return POM_OK;
	}

	int i;
	int len = 1;
	for (i = 1; i < argc; i++) 
		len += strlen(argv[i]);
	char *param = malloc(len);
	memset(param, 0, len);
	for (i = 1; i < argc; i++) {
		strcat(param, argv[i]);
		if (i != argc - 1)
			strcat(param, " ");

	}

	
	if (ptype_parse_val(p->value, param) != POM_OK) {
		mgmtsrv_send(c, "Could not parse \"%s\"\r\n", param);
	} else {
		main_config->input_serial++;
	}

	pthread_mutex_unlock(&rbuf->mutex);

	free(param);
	return POM_OK;
}

int mgmtcmd_input_parameter_reset(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 1)
		return MGMT_USAGE;

	if (pthread_mutex_lock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex");
		return POM_ERR;
	}

	if (!rbuf->i) {
		pthread_mutex_unlock(&rbuf->mutex);
		mgmtsrv_send(c, "No input configured yet. Use \"input type set <type>\" to choose an input\r\n");
		return POM_OK;
	}

	if (rbuf->i->running) {
		pthread_mutex_unlock(&rbuf->mutex);
		mgmtsrv_send(c, "Input is running. You need to stop it before doing any change\r\n");
		return POM_OK;
	}

	struct input_param *p = rbuf->i->mode->params;

	while (p) {
		if (!strcmp(p->name, argv[0]))
			break;
		p = p->next;
	}

	if (!p) {
		pthread_mutex_unlock(&rbuf->mutex);
		mgmtsrv_send(c, "Parameter %s does not exists\r\n", argv[0]);
		return POM_OK;
	}

	if (ptype_parse_val(p->value, p->defval) != POM_OK) {
		mgmtsrv_send(c, "Could not parse \"%s\"\r\n", p->defval);
	} else {
		main_config->input_serial++;
	}

	pthread_mutex_unlock(&rbuf->mutex);

	return POM_OK;
}

struct mgmt_command_arg* mgmtcmd_input_parameter_set_completion(int argc, char *argv[]) {
	
	if (argc != 3)
		return NULL;

	if (!rbuf->i || !rbuf->i->mode)
		return NULL;

	struct mgmt_command_arg *res = NULL;

	struct input_param *params = rbuf->i->mode->params;

	while (params) {
		struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
		memset(item, 0, sizeof(struct mgmt_command_arg));
		item->word = malloc(strlen(params->name) + 1);
		strcpy(item->word, params->name);
	
		item->next = res;
		res = item;

		params = params->next;
	}

	return res;
}

int mgmtcmd_input_help(struct mgmt_connection *c, int argc, char *argv[]) {


	int single = 0, id = 0, displayed = 0;
	if (argc >= 1) {
		single = 1;
		input_lock(1);
		id = input_register(argv[0]);
		if (id == POM_ERR) {
			input_unlock();
			mgmtsrv_send(c, "Non existing input %s\r\n", argv[0]);
			return POM_OK;
		}
		input_unlock();
	}

	input_lock(0);
	for (; id < MAX_INPUT; id++) {
		char *name = input_get_name(id);
		if (!name)
			continue;

		displayed++;

		mgmtsrv_send(c, "Input %s :\r\n", name);

		struct input_mode *im = inputs[id]->modes;

		while (im) {

			mgmtsrv_send(c, "  mode %s : %s\r\n", im->name, im->descr);

			struct input_param* ip = im->params;
			if (!ip) {
				mgmtsrv_send(c, "    no parameter for this mode\r\n");
			} else {
				while (ip) {
					char *ptype_name = ptype_get_name(ip->value->type);
					if (!ptype_name)
						ptype_name = "unknown";
					mgmtsrv_send(c, "    %s (%s) : %s (default : '%s')\r\n", ip->name, ptype_name, ip->descr, ip->defval);
					
					ip = ip->next;
				}
			}
			im = im->next;
		}

		mgmtsrv_send(c, "\r\n");

		if (single)
			break;
	}

	input_unlock();

	if (!displayed)
		mgmtsrv_send(c, "No input loaded\r\n");

	return POM_OK;
}

int mgmtcmd_input_load(struct mgmt_connection *c, int argc, char*argv[]) {

	if (argc != 1)
		return MGMT_USAGE;

	input_lock(1);

	if (input_get_type(argv[0]) != POM_ERR) {
		input_unlock();
		mgmtsrv_send(c, "Input %s is already registered\r\n", argv[0]);
		return POM_OK;
	}

	int id = input_register(argv[0]);
	if (id == POM_ERR)
		mgmtsrv_send(c, "Error while loading input %s\r\n", argv[0]);
	else
		mgmtsrv_send(c, "Input %s regitered with id %u\r\n", argv[0], id);

	input_unlock();

	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_input_avail_completion(int argc, char *argv[]) {

	if (argc != 2)
		return NULL;

	struct mgmt_command_arg *res = NULL;
	res = mgmtcmd_list_modules("input");
	return res;
}

int mgmtcmd_input_unload(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;


	input_lock(1);
	int id = input_get_type(argv[0]);

	if (id == POM_ERR) {
		input_unlock();
		mgmtsrv_send(c, "Input %s not loaded\r\n", argv[0]);
		return POM_OK;
	}

	if (rbuf->i && rbuf->i->type == id) {
		input_unlock();
		mgmtsrv_send(c, "Input %s is still in use. Cannot unload it\r\n", argv[0]);
		return POM_OK;
	}

	if (input_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Input unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading input\r\n");
	}
	input_unlock();
	
	return POM_OK;

}

struct mgmt_command_arg* mgmtcmd_input_unload_completion(int argc, char *argv[]) {

	struct mgmt_command_arg *res = NULL;

	if (argc != 2)
		return NULL;

	input_lock(0);

	int i;
	for (i = 0; i < MAX_INPUT; i++) {
		if (inputs[i]) {
			struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
			memset(item, 0, sizeof(struct mgmt_command_arg));
			char *name = inputs[i]->name;
			item->word = malloc(strlen(name) + 1);
			strcpy(item->word, name);
			item->next = res;
			res = item;
		}

	}

	input_unlock();

	return res;
}
