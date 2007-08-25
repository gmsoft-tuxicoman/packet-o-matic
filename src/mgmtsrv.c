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

#define TELNET_SUBOPT_MAX 256
#define READ_BUFF_LEN 2048

#include "common.h"
#include "mgmtsrv.h"
#include "mgmtcmd.h"

#include <signal.h>

#define TELCMDS 1 // will populate the table telcmds
#define TELOPTS 1 // will populate the table telopts
#include <arpa/telnet.h>

struct mgmt_connection *conn_head;
struct mgmt_connection *conn_tail;

struct mgmt_command *cmds;

int mgmtsrv_init() {


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

	if (getaddrinfo(NULL, PORT, &hints, &res) < 0) {
		strerror_r(errno, errbuff, 256);
		dprint("Error while finding an address to listen on : %s\n", errbuff);
		return MGMT_ERR;
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

		dprint("Management console listening on %s\n", host);
	
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
		return MGMT_ERR;
	}

	// register all the commands
	mgmtcmd_register_all();


	return MGMT_OK;

}


int mgmtsrv_process() {

	fd_set fds;

	FD_ZERO(&fds);
	int max_fd = 0;

	struct mgmt_connection *cc = conn_head;
	while(cc) {
		if (cc->closed) { // cleanup this connection entry if it was closed earlier
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
		return MGMT_OK;

	cc = conn_head;
	while(cc) {

		if (FD_ISSET(cc->fd, &fds)) {
			if (cc->listening)
				return mgmtsrv_accept_connection(cc);
			return mgmtsrv_read_socket(cc);
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

	char commands[] = { IAC, WILL, TELOPT_ECHO, IAC, WILL, TELOPT_SGA, IAC, DO, TELOPT_NAWS, IAC, DONT, TELOPT_LINEMODE };
	send(new_cc->fd, commands, sizeof(commands), 0);

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

int mgmtsrv_read_socket(struct mgmt_connection *c) {

	
	int res;
	unsigned int len = 0;
	unsigned char buffer[READ_BUFF_LEN];
	unsigned char telnet_opt[TELNET_SUBOPT_MAX];

	while ((res = read(c->fd, buffer + len,  READ_BUFF_LEN - len)) > 0) {
		len += res;
	}

	if (res == 0) {
		ndprint("Connection %u closed by foreign host\n", c->fd);
		mgmtsrv_close_connection(c);
		return MGMT_OK;
	}

	int my_errno = errno;
	if (my_errno != EAGAIN) {
		ndprint("Error while reading from socket %u\n", c->fd);
		mgmtsrv_close_connection(c);
		return MGMT_OK;
	}

	int i, msg_type = 0; // msg_type is 1 when we are threating a out of band message (telnet opt), it's 2 when we are threating an escape sequence
	for (i = 0; i < len; i++) {

		switch (msg_type) {

			case 1:  // Handle telnet option
				switch (buffer[i]) {

					case DO:
					case DONT:
					case WILL:
					case WONT:
						// Those commands take 1 extra byte
						memcpy(telnet_opt, buffer + i, 2);
						mgmtsrv_process_telnet_option(c, telnet_opt, 2);
						i++;
						msg_type = 0;
						continue;

					case SB: {
						unsigned int opt_len;
						// Need to find the end of the suboption
						for (opt_len = 0; i < len && opt_len < TELNET_SUBOPT_MAX; i++) {
							if (buffer[i] == IAC) { // Check if it's the end of the option or doubled IAC
								if (buffer[i + 1] == IAC) { // It's doubled IAC
									telnet_opt[opt_len] = IAC;
									i++;
									continue;
								} else if (buffer[i + 1] == SE) { // End of suboption
									mgmtsrv_process_telnet_option(c, telnet_opt, opt_len);
									i++;
									msg_type = 0;
									break;
								} else {
									dprint("Warning, unexpected value while reading telnet suboption : %hhu\n", buffer[i]);
									continue;
								}
							}

							// This byte is part of the suboption
							telnet_opt[opt_len] = buffer[i];
							opt_len++;
						}
						break;
					}

					case IAC: // This is a doubled IAC => interpret as a byte of value 255
						mgmtsrv_process_key(c, buffer[i]);

					default:
						msg_type = 0;
						continue;
				}
				break;

			case 2: // Handle escape sequence
				if (i + 1 > len || buffer[i] != '[') {
					dprint("Invalid escape sequence\n");
					msg_type = 0;
					break;
				}
				i++;
				switch (buffer[i]) {
					case 'A': // up arrow
						dprint("up arrow pressed\n");
						break;
					case 'B': // down arrow
						dprint("down arrow pressed\n");
						break;
					case 'C': // right arrow
						if (c->cursor_pos < c->cmdlen) {
							char chr[2];
							chr[0] = c->cmd[c->cursor_pos];
							chr[1] = 0;
							mgmtsrv_send(c, chr);
							c->cursor_pos++;
						}	
						break;
					case 'D': // left arrow
						if (c->cursor_pos > 0) {
							mgmtsrv_send(c, "\b");
							c->cursor_pos--;
						}
						break;
					default: // not handled
						ndprint("Unknown escape sequence pressed : %c\n", buffer[i]);
						
					msg_type = 0;
				}
				break;

			default: // Normal key is pressed
				if (buffer[i] == IAC) {
					
					// this starts a new msg_type message
					msg_type = 1;
					continue;

				} else if (buffer[i] == 0x1B)  { // 0x1B = ESC
					msg_type = 2;
					continue;
				}
				mgmtsrv_process_key(c, buffer[i]);
		}


	}

	return MGMT_OK;

}


int mgmtsrv_process_telnet_option(struct mgmt_connection *c, unsigned char *opt, unsigned int len) {

#ifdef NDEBUG

	if (opt[0] == SB) {
		ndprint("Got telnet suboption %s\n", TELOPT(opt[1]));
	} else {

		ndprint("Got telnet option %s %s\n", TELCMD(opt[0]), TELOPT(opt[1]));
	}

#endif

	switch (opt[1]) { // Handle the stuff we support
		case TELOPT_ECHO:
			switch (opt[0]) {
				case WILL: // We sent the DO already
				case DO: // Good, that's what we were waiting for
					break;

				case WONT:
				case DONT: {
					// The remote client sux, closing connection (ok this is against RFC but I don't feel like supporting this as well)
					char *error_msg = "\r\nYou're telnet client doesn't support the TELNET ECHO mode. Closing connection\r\n";
					send(c->fd, error_msg, strlen(error_msg), 0);
					break;
				}
			}
			break;
		case TELOPT_NAWS:
			switch (opt[0]) {
				case WILL:
				case DO:
					break; // That's what we need
				case DONT:
				case WONT:
					c->win_x = 80;
					c->win_y = 24;
					break;
				case SB:
					c->win_x = opt[2] * 0x100;
					c->win_x += opt[3];
					c->win_y = opt[4] * 0x100;
					c->win_y += opt[5];
					ndprint("New remote window size for connection %u is %ux%u\n", c->fd, c->win_x, c->win_y);
			}
			break;
		case TELOPT_SGA:
			switch (opt[0]) {
				case WILL: // We sent the DO already
				case DO: // Good, that's what we were waiting for
					break;

				case WONT:
				case DONT: {
					// The remote client sux, closing connection (ok this is against RFC but I don't feel like supporting this as well)
					char *error_msg = "\r\nYou're telnet client doesn't support the TELNET SUPPRESS GO AHEAD option. Closing connection\r\n";
					send(c->fd, error_msg, strlen(error_msg), 0);
					break;
				}
			}
			break;

		default: { // We don't know about the rest
			char deny_msg[3];
			deny_msg[0] = IAC;
			deny_msg[2] = opt[1];
			switch (opt[0]) {
				case DO:
					deny_msg[1] = WONT;
					break;
				case WILL:
					deny_msg[1] = DONT;
					break;
				default:
					return MGMT_OK;

			}
			send(c->fd, deny_msg, 3, 0);

		}
	}


	return MGMT_OK;

}

int mgmtsrv_process_key(struct mgmt_connection *c, unsigned char key) {

	switch (key) {
		case 0: // ignore this one
			break;

		case 3: { // Ctrl-C
			mgmtsrv_send(c, "\r\n" MGMT_CMD_PROMPT);
			memset(c->cmd, 0, MGMT_CMD_BUFF_LEN);
			c->cmdlen = 0;
			c->cursor_pos = 0;
			break;
		}

		case 4: // Ctrl-D
			if (c->cmdlen == 0)
				mgmtcmd_exit(c);
			break;

		case '\b': { // backspace
			if (c->cmdlen == 0 || c->cursor_pos == 0)
				break;

			c->cursor_pos--;

			int i;
			for (i = c->cursor_pos; i < c->cmdlen; i++) {
				c->cmd[i] = c->cmd[i + 1];
			}
			mgmtsrv_send(c, "\b");
			mgmtsrv_send(c, c->cmd + c->cursor_pos);
			mgmtsrv_send(c, " ");
			for (i = c->cursor_pos; i < c->cmdlen; i++)
				mgmtsrv_send(c, "\b");
		
			c->cmdlen--;
			c->cmd[c->cmdlen] = 0;
			break;
		}

		case '\r': { // carriage return
			mgmtsrv_process_command(c);
			mgmtsrv_send(c,  "\r\n" MGMT_CMD_PROMPT);
			memset(c->cmd, 0, MGMT_CMD_BUFF_LEN);
			c->cmdlen = 0;
			c->cursor_pos = 0;
			break;
		}

		case '\t': // tab completion
		case '?': { // completion
			mgmtsrv_send(c, "\r\nCompletion not implemented (yet :)\r\n" MGMT_CMD_PROMPT);
			mgmtsrv_send(c, c->cmd);
			c->cursor_pos = c->cmdlen;
			break;
		}

		default: 
			if (c->cmdlen >= MGMT_CMD_BUFF_LEN) {
				mgmtsrv_send(c, "\r\nCommand too long\r\n" MGMT_CMD_PROMPT);
				mgmtsrv_send(c, c->cmd);
			} else {
				ndprint("Got key 0x%x\n", key);
				int i;
				for (i = c->cmdlen + 1; i > c->cursor_pos; i--)
					c->cmd[i] = c->cmd[i - 1];
				c->cmd[c->cursor_pos] = key;
				mgmtsrv_send(c, c->cmd + c->cursor_pos);
				for (i = c->cmdlen; i > c->cursor_pos; i--)
					mgmtsrv_send(c, "\b");
				c->cmdlen++;
				c->cursor_pos++;

			}
	}


	return MGMT_OK;

}

int mgmtsrv_register_command(struct mgmt_command *cmd) {


	if (!cmds) {
		cmds = cmd;
		return MGMT_OK;
	}

	struct mgmt_command *tmp = cmds;

	while (tmp->next) {
		tmp = tmp->next;
	}

	tmp->next = cmd;

	return MGMT_OK;

}

int mgmtsrv_process_command(struct mgmt_connection *c) {

	// Let's start by splitting this line
	char *words[MGMT_MAX_CMD_WORDS];
	unsigned int words_count = 0, i;
	char *str, *saveptr, *token;

	for (i = 0; i < MGMT_MAX_CMD_WORDS; i++)
		words[i] = 0;

	for (str = c->cmd; ;str = NULL) {
		token = strtok_r(str, " ", &saveptr);
		if (token == NULL)
			break;
		if (strlen(token) == 0)
			continue;
		words[words_count] = token;
		words_count++;
	}

	if (words_count == 0)
		return MGMT_OK;
	
	mgmtsrv_send(c, "\r\n");

	struct mgmt_command *tmpcmd = cmds;

	while (tmpcmd) {
		for (i = 0; i < words_count; i++) {
			if (strcmp(words[i], tmpcmd->words[i]))
				break;	
		}
		if (i == words_count && tmpcmd->words[i] == NULL) {
			return (*tmpcmd->callback_func) (c);
		}
		tmpcmd = tmpcmd->next;
	}
	
	mgmtsrv_send(c, "No such command");

	return MGMT_OK;

}

int mgmtsrv_close_connection(struct mgmt_connection *c) {


	ndprint("Closing socket %u\n", c->fd);
	close(c->fd);
	c->closed = 1;

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


int mgmtsrv_send(struct mgmt_connection *c, char* msg) {

	return send(c->fd, msg, strlen(msg), 0);
}