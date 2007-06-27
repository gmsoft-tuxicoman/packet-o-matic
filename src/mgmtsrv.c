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

#define PORT "4655"
#define WAIT_CONNS 2


#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include "common.h"
#include "mgmtsrv.h"

#include <errno.h>
#include <signal.h>


struct mgmt_connection *conn_head;
struct mgmt_connection *conn_tail;

int mgmtsrv_init() {


	// first of all, ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);

	conn_head = NULL;
	conn_tail = NULL;


	struct addrinfo hints, *res;
	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(NULL, PORT, &hints, &res) < 0) {
		dprint("Error while finding an address to listen on\n");
		return MGMT_ERR;
	}

	struct addrinfo *tmpres = res;
	int sockfd;
	while (tmpres) {
		if (tmpres->ai_family != AF_INET && tmpres->ai_family != AF_INET6)
			continue;

		sockfd = socket(tmpres->ai_family, tmpres->ai_socktype, tmpres->ai_protocol);
		if (sockfd < 0) {
			dprint("Error while creating socket\n");
			tmpres = tmpres->ai_next;
			continue;
		}

		if (bind(sockfd, tmpres->ai_addr, tmpres->ai_addrlen) < 0) {
			dprint("Error while binding socket\n");
			close(sockfd);
			tmpres = tmpres->ai_next;
			continue;
		}

		if (listen(sockfd, WAIT_CONNS)) {
			dprint("Error while switching socket to listen state\n");
			close(sockfd);
			tmpres = tmpres->ai_next;
			continue;
		}

		struct mgmt_connection *conn = malloc(sizeof(struct mgmt_connection));
		bzero(conn, sizeof(struct mgmt_connection));
		conn->fd = sockfd;
		conn->listening = 1;

		if (!conn_head) {
			conn_head = conn;
			conn_tail = conn;
		} else {
			conn_tail->next = conn;
			conn->prev = conn_tail;
			conn_tail = conn;
		}

	}

	freeaddrinfo(res);

	if (!conn_head) {
		dprint("Could not open a single socket\n");
		return MGMT_ERR;
	}

	return MGMT_OK;

}


int mgmtsrv_process() {

	fd_set fds;

	FD_ZERO(&fds);
	int max_fd = 0;

	struct mgmt_connection *cc = conn_head;
	while(cc) {
		FD_SET(cc->fd, &fds);
		if (cc->fd > max_fd)
			max_fd = cc->fd;
		cc = cc->next;
	}

	struct timeval tv;
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	if (select(max_fd + 1, &fds, NULL, NULL, &tv) <= 0)
		return MGMT_OK;

	cc = conn_head;
	while(cc) {
		if (FD_ISSET(cc->fd, &fds)) {
			if (cc->listening)
				return mgmtsrv_accept_connection(cc);
			return mgmtsrv_read_command(cc);
		}
		cc = cc->next;
	}

	return MGMT_OK;

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
		return MGMT_ERR;
	}

	int flags = fcntl(new_cc->fd, F_GETFL);
	if (flags < 0) {
		free(new_cc);
		dprint("Error while getting flags of fd %d\n", new_cc->fd);
		return MGMT_ERR;
	}

	if (fcntl(new_cc->fd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
		free(new_cc);
		dprint("Unable to set non blocking flag for socket %d\n", new_cc->fd);
		return MGMT_ERR;
	}

	char host[NI_MAXHOST], port[NI_MAXSERV];
	bzero(host, NI_MAXHOST);
	bzero(port, NI_MAXSERV);

	getnameinfo((struct sockaddr*)&remote_addr, remote_addr_len, host, NI_MAXHOST, port, NI_MAXSERV, NI_NUMERICHOST);

	char *welcome_msg = "\nThis is packet-o-matic. \nCopyright Guy Martin 2006-2007\n\n" MGMT_CMD_PROMPT;


	if (send(new_cc->fd, welcome_msg, strlen(welcome_msg), 0) == -1) {
		free(new_cc);
		dprint("Error while accepting new connection from %s:%s\n", host, port);
		return MGMT_ERR;
	}

	if (conn_tail) {
		conn_tail->next = new_cc;
		new_cc->prev = conn_tail;
	} else {
		conn_head = new_cc;
	}

	conn_tail = new_cc;
	dprint("Accepted management connection from %s\n", host);
	return MGMT_OK;

}

int mgmtsrv_read_command(struct mgmt_connection *c) {

	int res; 
	size_t pos = 0;
	bzero(c->cmd, MGMT_CMD_BUFF_LEN);

	while ((res = read(c->fd, c->cmd + pos, MGMT_CMD_BUFF_LEN - pos - 1)) > 0) {
		pos += res;
	}
	int my_errno = errno;

	if (my_errno != EAGAIN) {
		ndprint("Error while reading from socket %u\n", c->fd);
		mgmtsrv_close_connection(c);
		return MGMT_OK;
	}


	// remove \n\r from command
	int cmdlen = strlen(c->cmd);
	while (cmdlen > 0) {
		if (c->cmd[cmdlen - 1] == '\n' || c->cmd[cmdlen - 1] == '\r') {
			cmdlen--;
			c->cmd[cmdlen] = 0;
		} else
			break;
	}

	ndprint("Got command \"%s\"\n", c->cmd);

	if (!strcmp(c->cmd, "quit"))
		return mgmtsrv_close_connection(c);

	write(c->fd, MGMT_CMD_PROMPT, strlen(MGMT_CMD_PROMPT));

	return MGMT_OK;

}


int mgmtsrv_close_connection(struct mgmt_connection *c) {


	ndprint("Closing socket %u\n", c->fd);
	close(c->fd);
	if (!c->prev)
		conn_head = c->next;
	else
		c->prev->next = c->next;

	if (!c->next)
		conn_tail = c->prev;
	else
		c->next->prev = c->prev;


	free(c);

	return MGMT_OK;

}

int mgmtsrv_cleanup() {


	struct mgmt_connection *tmp;
	while (conn_head) {
		close(conn_head->fd);
		tmp = conn_head;
		conn_head = conn_head->next;
		free(tmp);

	}

	return MGMT_OK;

}
