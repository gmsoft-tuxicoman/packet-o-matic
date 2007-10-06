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

#define NDEBUG

#define WAIT_CONNS 2

#define READ_BUFF_LEN 2048

#include "common.h"
#include "mgmtsrv.h"
#include "mgmtcmd.h"
#include "mgmtvty.h"

#include <signal.h>

struct mgmt_connection *conn_head;
struct mgmt_connection *conn_tail;

char *mgmt_password = NULL;

int mgmtsrv_init(const char *port) {


	// first of all, ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	conn_head = NULL;
	conn_tail = NULL;

	cmds = NULL;

	char errbuff[256];

	struct addrinfo hints, *res;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(NULL, port, &hints, &res) < 0) {
		strerror_r(errno, errbuff, 256);
		dprint("Error while finding an address to listen on : %s\n", errbuff);
		return POM_ERR;
	}

	struct addrinfo *tmpres = res;
	int sockfd;
	while (tmpres) {
		if (tmpres->ai_family != AF_INET && tmpres->ai_family != AF_INET6)
			continue;
 
		char host[NI_MAXHOST], port[NI_MAXSERV];
		bzero(host, NI_MAXHOST);
		bzero(port, NI_MAXSERV);

		getnameinfo((struct sockaddr*)tmpres->ai_addr, tmpres->ai_addrlen, host, NI_MAXHOST, port, NI_MAXSERV, NI_NUMERICHOST);

		sockfd = socket(tmpres->ai_family, tmpres->ai_socktype, tmpres->ai_protocol);
		if (sockfd < 0) {
			strerror_r(errno, errbuff, 256);
			dprint("Error while creating socket : %s\n", errbuff);
			tmpres = tmpres->ai_next;
			continue;
		}

		const int yes = 1;
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			strerror_r(errno, errbuff, 256);
			dprint("Error while setting REUSEADDR option on socket : %s\n", errbuff);
			close(sockfd);
			tmpres = tmpres->ai_next;
			continue;

		}

		if (bind(sockfd, tmpres->ai_addr, tmpres->ai_addrlen) < 0) {
			strerror_r(errno, errbuff, 256);
			dprint("Error while binding socket on address %s : %s\n", host, errbuff);
			close(sockfd);
			tmpres = tmpres->ai_next;
			continue;
		}

		if (listen(sockfd, WAIT_CONNS)) {
			strerror_r(errno, errbuff, 256);
			dprint("Error while switching socket to listen state : %s\n", errbuff);
			close(sockfd);
			tmpres = tmpres->ai_next;
			continue;
		}

		struct mgmt_connection *conn = malloc(sizeof(struct mgmt_connection));
		bzero(conn, sizeof(struct mgmt_connection));
		conn->fd = sockfd;
		conn->listening = 1;

		dprint("Management console listening on %s:%s\n", host, port);
	
		if (!conn_head) {
			conn_head = conn;
			conn_tail = conn;
		} else {
			conn_tail->next = conn;
			conn->prev = conn_tail;
			conn_tail = conn;
		}

		tmpres = tmpres->ai_next;
	}

	freeaddrinfo(res);

	if (!conn_head) {
		dprint("Could not open a single socket\n");
		return POM_ERR;
	}

	// register all the commands
	mgmtcmd_register_all();


	return POM_OK;

}


int mgmtsrv_process() {

	fd_set fds;

	FD_ZERO(&fds);
	int max_fd = 0;

	struct mgmt_connection *cc = conn_head;
	while(cc) {
		if (cc->state == MGMT_STATE_CLOSED) { // cleanup this connection entry if it was closed earlier
			
			int i;
			for (i = 0; i < MGMT_CMD_HISTORY_SIZE; i++)
				if (cc->cmds[i])
					free(cc->cmds[i]);

			struct mgmt_connection *tmp = cc->next;
			if (!cc->prev)
				conn_head = cc->next;
			 else 
				cc->prev->next = cc->next;

			if (!cc->next)
				conn_tail = cc->prev;
			else
				cc->next->prev = cc->prev;

			free(cc);
			cc = tmp;
			continue;
		}


		FD_SET(cc->fd, &fds);
		if (cc->fd > max_fd)
			max_fd = cc->fd;
		cc = cc->next;
	}

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	if (select(max_fd + 1, &fds, NULL, NULL, &tv) <= 0)
		return POM_OK;

	cc = conn_head;
	while(cc) {

		if (FD_ISSET(cc->fd, &fds)) {
			if (cc->listening)
				return mgmtsrv_accept_connection(cc);
			return mgmtsrv_read_socket(cc);
		}
		cc = cc->next;
	}

	return POM_OK;

}

int mgmtsrv_accept_connection(struct mgmt_connection *c) {

	struct mgmt_connection *new_cc = malloc(sizeof(struct mgmt_connection));
	bzero(new_cc, sizeof(struct mgmt_connection));

	struct sockaddr_storage remote_addr;
	socklen_t remote_addr_len = sizeof(struct sockaddr_storage);

	new_cc->fd = accept(c->fd, (struct sockaddr *) &remote_addr, &remote_addr_len);

	if (new_cc->fd < 0) {
		free(new_cc);
		dprint("Error while accepting new connection\n");
		return POM_ERR;
	}

	int flags = fcntl(new_cc->fd, F_GETFL);
	if (flags < 0) {
		free(new_cc);
		dprint("Error while getting flags of fd %d\n", new_cc->fd);
		return POM_ERR;
	}

	if (fcntl(new_cc->fd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
		free(new_cc);
		dprint("Unable to set non blocking flag for socket %d\n", new_cc->fd);
		return POM_ERR;
	}

	char host[NI_MAXHOST], port[NI_MAXSERV];
	bzero(host, NI_MAXHOST);
	bzero(port, NI_MAXSERV);

	getnameinfo((struct sockaddr*)&remote_addr, remote_addr_len, host, NI_MAXHOST, port, NI_MAXSERV, NI_NUMERICHOST);

	// Init cmd line buffer
	new_cc->cmds[0] = malloc(1);
	new_cc->cmds[0][0] = 0;
	
	new_cc->state = MGMT_STATE_INIT;

	if (conn_tail) {
		conn_tail->next = new_cc;
		new_cc->prev = conn_tail;
	} else {
		conn_head = new_cc;
	}

	conn_tail = new_cc;
	dprint("Accepted management connection from %s\n", host);


	return mgmtvty_init(new_cc);

}

int mgmtsrv_read_socket(struct mgmt_connection *c) {

	
	int res;
	unsigned int len = 0;
	unsigned char buffer[READ_BUFF_LEN];

	while ((res = read(c->fd, buffer + len,  READ_BUFF_LEN - len)) > 0) {
		len += res;
	}

	if (res == 0) {
		ndprint("Connection %u closed by foreign host\n", c->fd);
		mgmtsrv_close_connection(c);
		return POM_OK;
	}

	int my_errno = errno;
	if (my_errno != EAGAIN) {
		ndprint("Error while reading from socket %u\n", c->fd);
		mgmtsrv_close_connection(c);
		return POM_OK;
	}

	mgmtvty_process(c, buffer, len);

	return POM_OK;
}


int mgmtsrv_register_command(struct mgmt_command *cmd) {


	if (!cmds) {
		cmds = cmd;
		return POM_OK;
	}

	struct mgmt_command *tmp = cmds;

	while (tmp->next) {
		tmp = tmp->next;
	}

	tmp->next = cmd;

	return POM_OK;

}

int mgmtsrv_process_command(struct mgmt_connection *c) {

	// Let's start by splitting this line
	char *words[MGMT_MAX_CMD_WORDS_ARGS];
	unsigned int words_count = 0, i;
	char *str, *saveptr, *token;

	for (i = 0; i < MGMT_MAX_CMD_WORDS_ARGS; i++)
		words[i] = 0;

	// Use temporary buffer to avoid modifying the command history
	char *tmpcmdstr = malloc(strlen(c->cmds[c->curcmd]) + 1);
	strcpy(tmpcmdstr, c->cmds[c->curcmd]);

	for (str = tmpcmdstr; ;str = NULL) {
		if (words_count >= MGMT_MAX_CMD_WORDS_ARGS) {
			mgmtsrv_send(c, "\r\nToo many arguments\r\n");
			free(tmpcmdstr);
			return POM_OK;
		}
		token = strtok_r(str, " ", &saveptr);
		if (token == NULL)
			break;
		if (strlen(token) == 0)
			continue;
		words[words_count] = token;
		words_count++;
	}

	mgmtsrv_send(c, "\r\n");

	if (words_count == 0) {
		free(tmpcmdstr);
		return POM_OK;
	}
	
	struct mgmt_command *tmpcmd = cmds;

	while (tmpcmd) {
		for (i = 0; i < words_count && tmpcmd->words[i]; i++) {
			if (strcmp(words[i], tmpcmd->words[i]))
				break;	
		}
		unsigned int cmd_words_count;
		for (cmd_words_count = 0; tmpcmd->words[cmd_words_count] && cmd_words_count < MGMT_MAX_CMD_WORDS; cmd_words_count++);

		if (words_count >= i && i == cmd_words_count) {
			int res;
			res = (*tmpcmd->callback_func) (c, words_count - cmd_words_count, words + cmd_words_count);

			free(tmpcmdstr);
			if (res == MGMT_USAGE)
				return mgmtvty_print_usage(c, tmpcmd);
			else
				return res;
		}
		tmpcmd = tmpcmd->next;
	}
	
	mgmtsrv_send(c, "No such command\r\n");

	free(tmpcmdstr);
	return POM_OK;

}

int mgmtsrv_close_connection(struct mgmt_connection *c) {


	ndprint("Closing socket %u\n", c->fd);
	close(c->fd);
	c->state = MGMT_STATE_CLOSED;

	return POM_OK;

}

int mgmtsrv_cleanup() {


	struct mgmt_connection *tmp;
	while (conn_head) {
		close(conn_head->fd);
		int i;
		for (i = 0; i < MGMT_CMD_HISTORY_SIZE; i++)
			if (conn_head->cmds[i])
				free(conn_head->cmds[i]);
		tmp = conn_head;
		conn_head = conn_head->next;
		free(tmp);

	}

	if (mgmt_password)
		free(mgmt_password);

	return POM_OK;
}


int mgmtsrv_send(struct mgmt_connection *c, char* msg) {

	// Do not echo anything if we are processing password
	if (c->state == MGMT_STATE_PASSWORD)
		return 0;

	return send(c->fd, msg, strlen(msg), 0);
}

int mgmtsrv_set_password(const char *password) {

	if (mgmt_password)
		free(mgmt_password);

	if (!password) {
		mgmt_password = NULL;
		return POM_OK;
	}
	
	mgmt_password = malloc(strlen(password) + 1);
	strcpy(mgmt_password, password);
	return POM_OK;
}

const char *mgmtsrv_get_password() {

	return mgmt_password;
}
