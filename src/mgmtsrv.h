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


#ifndef __MGMTSRV_H__
#define __MGMTSRV_H__

#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <errno.h>

struct mgmt_command *cmds;

// Command functions return this value if it's needed to print the usage
#define MGMT_USAGE -2

// Maximum number of words in a command declaration
#define MGMT_MAX_CMD_WORDS 16

// Maximum number of words in a command entered in the console
#define MGMT_MAX_CMD_WORDS_ARGS 2048

#define MGMT_CMD_HISTORY_SIZE 100

#define MGMT_CMD_PROMPT "pom> "

struct mgmt_connection {
	int fd; // fd of the socket
	int listening; // is it a listening socket ?
	int closed; // was the socket closed earlier ?
	char *cmds[MGMT_CMD_HISTORY_SIZE];
	size_t curcmd; // current command in the history
	size_t cursor_pos; // position of the cursor on the line
	struct mgmt_connection *prev;
	struct mgmt_connection *next;
	uint16_t win_x, win_y; // size of the remote window

};


struct mgmt_command {

	char *words[MGMT_MAX_CMD_WORDS + 1];
	char *help;
	char *usage;

	int (*callback_func) (struct mgmt_connection *c, int argc, char *argv[]);

	struct mgmt_command *next;

};


int mgmtsrv_init();
int mgmtsrv_process();
int mgmtsrv_read_socket(struct mgmt_connection *c);
int mgmtsrv_cleanup();

int mgmtsrv_accept_connection(struct mgmt_connection *c);
int mgmtsrv_register_command(struct mgmt_command *cmd);
int mgmtsrv_process_command(struct mgmt_connection *c);
int mgmtsrv_close_connection(struct mgmt_connection *c);

int mgmtsrv_send(struct mgmt_connection *c, char* msg);

#endif

