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


#include "mgmtcmd_input.h"

#include <pthread.h>

#define MGMT_INPUT_COMMANDS_NUM 8

struct mgmt_command mgmt_input_commands[MGMT_INPUT_COMMANDS_NUM] = {

	{
		.words = { "show", "input", NULL },
		.help = "Display informations about the input in use",
		.callback_func = mgmtcmd_show_input,
	},

	{
		.words = { "start", "input", NULL },
		.help = "Start the input",
		.callback_func = mgmtcmd_start_input,
	},

	{
		.words = { "stop", "input", NULL },
		.help = "Stop the input",
		.callback_func = mgmtcmd_stop_input,
	},

	{
		.words = { "set", "input", "type", NULL },
		.help = "Select another type of input",
		.callback_func = mgmtcmd_set_input_type,
		.usage = "set input type <type>",
	},

	{
		.words = { "set", "input", "mode", NULL },
		.help = "Change the mode of the input",
		.callback_func = mgmtcmd_set_input_mode,
		.usage = "set input mode <mode>",
	},

	{
		.words = { "set", "input", "parameter", NULL },
		.help = "Change the value of a input parameter",
		.callback_func = mgmtcmd_set_input_parameter,
		.usage = "set input parameter <parameter> <value>",
	},

	{
		.words = { "load", "input", NULL },
		.help = "Load an input from the system",
		.usage = "load input <input>",
		.callback_func = mgmtcmd_load_input,
	},

	{
		.words = { "unload", "input", NULL },
		.help = "Unload an input from the system",
		.usage = "unload input <input>",
		.callback_func = mgmtcmd_unload_input,
	},
};

int mgmtcmd_input_register_all() {

	int i;


	for (i = 0; i < MGMT_INPUT_COMMANDS_NUM; i++) {
		mgmtsrv_register_command(&mgmt_input_commands[i]);
	}

	return POM_OK;
}

int mgmtcmd_show_input(struct mgmt_connection *c, int argc, char *argv[]) {

	struct input* i = main_config->input;
	if (!i) {
		mgmtsrv_send(c, "No input configured yet. Use \"set input type <type>\" to choose an input\r\n");
		return POM_OK;
	}

	mgmtsrv_send(c, "Current input : ");
	mgmtsrv_send(c, input_get_name(i->type));
	mgmtsrv_send(c, ", mode ");
	mgmtsrv_send(c, i->mode->name);

	char pkts[16], bytes[16];
	ptype_print_val(i->pkt_cnt, pkts, sizeof(pkts));
	ptype_print_val(i->byte_cnt, bytes, sizeof(bytes));
	mgmtsrv_send(c, " (%s %s, %s %s)", pkts, i->pkt_cnt->unit, bytes, i->byte_cnt->unit);

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

int mgmtcmd_start_input(struct mgmt_connection *c, int argc, char *argv[]) {


	if (rbuf->state != rb_state_closed) {
		mgmtsrv_send(c, "Input already started\r\n");
		return POM_OK;
	}

	if (!main_config->input) {
		mgmtsrv_send(c, "No input configured yet. Use \"set input type <type>\" to choose an input\r\n");
		return POM_OK;
	}

	if (start_input(rbuf) == POM_ERR)
		mgmtsrv_send(c, "Error while opening input\r\n");
	return POM_OK;

}

int mgmtcmd_stop_input(struct mgmt_connection *c, int argc, char *argv[]) {


	if (rbuf->state == rb_state_closed) {
		mgmtsrv_send(c, "Input already stopped\r\n");
		return POM_OK;
	}

	stop_input(rbuf);
	return POM_OK;

}

int mgmtcmd_set_input_type(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	if (rbuf->i && rbuf->i->running) {
		mgmtsrv_send(c, "Input is running. You need to stop it before doing any change\r\n");
		return POM_OK;
	}

	if (pthread_mutex_lock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while locking the buffer mutex\r\n");
		return POM_ERR;
	}

	if (rbuf->i && !strcmp(argv[0], input_get_name(rbuf->i->type))) {
		mgmtsrv_send(c, "Input type is already %s\r\n", argv[0]);
		pthread_mutex_unlock(&rbuf->mutex);
		return POM_OK;
	}

	struct input *i;
	int input_type = input_register(argv[0]);
	if (input_type == POM_ERR) {
		mgmtsrv_send(c, "Unable to register input %s\r\n", argv[0]);
		pthread_mutex_unlock(&rbuf->mutex);
		return POM_OK;
	}

	i = input_alloc(input_type);

	if (!i) {
		mgmtsrv_send(c, "Unable to allocate input %s\r\n", argv[0]);
		pthread_mutex_unlock(&rbuf->mutex);
		return POM_OK;
	}
	if (rbuf->i)
		input_cleanup(rbuf->i);
	rbuf->i = i;
	main_config->input = i;

	if (pthread_mutex_unlock(&rbuf->mutex)) {
		pom_log(POM_LOG_ERR "Error while unlocking the buffer mutex\r\n");
		return POM_ERR;
	}

	return POM_OK;
}

int mgmtcmd_set_input_mode(struct mgmt_connection *c, int argc, char *argv[]) {

	if (argc < 1)
		return MGMT_USAGE;

	if (!rbuf->i) {
		mgmtsrv_send(c, "No input configured yet. Use \"set input type <type>\" to choose an input\r\n");
		return POM_OK;
	}

	if (rbuf->i->running) {
		mgmtsrv_send(c, "Input is running. You need to stop it before doing any change\r\n");
		return POM_OK;
	}

	if (input_set_mode(rbuf->i, argv[0]) != POM_OK) {
		mgmtsrv_send(c, "No mode %s for this input\r\n");
		return POM_OK;
	}

	return POM_OK;
}

int mgmtcmd_set_input_parameter(struct mgmt_connection *c, int argc, char *argv[]) {
	
	if (argc < 2)
		return MGMT_USAGE;

	if (!rbuf->i) {
		mgmtsrv_send(c, "No input configured yet. Use \"set input type <type>\" to choose an input\r\n");
		return POM_OK;
	}

	if (rbuf->i->running) {
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
		mgmtsrv_send(c, "Parameter %s does not exists\r\n", argv[0]);
		return POM_OK;
	}

	int i;
	int len = 0;
	for (i = 1; i < argc; i++) 
		len += strlen(argv[i]) + 1;
	char *param = malloc(len);
	memset(param, 0, len);
	for (i = 1; i < argc; i++) {
		strcat(param, argv[i]);
		if (i != argc - 1)
			strcat(param, " ");

	}

	
	if (ptype_parse_val(p->value, param) != POM_OK) {
		mgmtsrv_send(c, "Could not parse \"%s\"\r\n", param);
	}

	free(param);
	return POM_OK;
}

int mgmtcmd_load_input(struct mgmt_connection *c, int argc, char*argv[]) {

	if (argc != 1)
		return MGMT_USAGE;
	
	if (input_get_type(argv[0]) != POM_ERR) {
		mgmtsrv_send(c, "Input %s is already registered\r\n", argv[0]);
		return POM_OK;
	}

	int id = input_register(argv[0]);
	if (id == POM_ERR)
		mgmtsrv_send(c, "Error while loading input %s\r\n", argv[0]);
	else
		mgmtsrv_send(c, "Input %s regitered with id %u\r\n", argv[0], id);

	return POM_OK;

}

int mgmtcmd_unload_input(struct mgmt_connection *c, int argc, char *argv[]) {


	if (argc != 1)
		return MGMT_USAGE;

	int id = input_get_type(argv[0]);

	if (id == POM_ERR) {
		mgmtsrv_send(c, "Input %s not loaded\r\n", argv[0]);
		return POM_OK;
	}

	if (rbuf->i && rbuf->i->type == id) {
		mgmtsrv_send(c, "Input %s is still in use. Cannot unload it\r\n", argv[0]);
		return POM_OK;
	}

	reader_process_lock();
	if (input_unregister(id) != POM_ERR) {
		mgmtsrv_send(c, "Input unloaded successfully\r\n");
	} else {
		mgmtsrv_send(c, "Error while unloading input\r\n");
	}
	reader_process_unlock();
	
	return POM_OK;

}
