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
#include "mgmtsrv.h"
#include "mgmtvty.h"
#include "mgmtcmd.h"

#define TELNET_SUBOPT_MAX 256

#define TELCMDS 1 // will populate the table telcmds
#define TELOPTS 1 // will populate the table telopts
#include <arpa/telnet.h>

int mgmtvty_init(struct mgmt_connection *c) {


	if (c->state != MGMT_STATE_INIT) {
		pom_log(POM_LOG_ERR "Error, connection in wrong state\r\n");
		return POM_ERR;
	}

	mgmtsrv_send(c, "\nThis is packet-o-matic. \nCopyright Guy Martin 2006-2007\n\n");

	char commands[] = { IAC, WILL, TELOPT_ECHO, IAC, WILL, TELOPT_SGA, IAC, DO, TELOPT_NAWS, IAC, DONT, TELOPT_LINEMODE };
	send(c->fd, commands, sizeof(commands), 0);

	if (!mgmtsrv_get_password()) {
		mgmtsrv_send(c, MGMT_CMD_PROMPT);
		c->state = MGMT_STATE_AUTHED;
	} else {
		mgmtsrv_send(c, MGMT_CMD_PWD_PROMPT);
		c->state = MGMT_STATE_PASSWORD;
	}


	return POM_OK;

}


int mgmtvty_process(struct mgmt_connection *c, unsigned char *buffer, unsigned int len) {

	unsigned char telnet_opt[TELNET_SUBOPT_MAX];
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
						mgmtvty_process_telnet_option(c, telnet_opt, 2);
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
									mgmtvty_process_telnet_option(c, telnet_opt, opt_len);
									i++;
									msg_type = 0;
									break;
								} else {
									pom_log(POM_LOG_WARN "Warning, unexpected value while reading telnet suboption : %hhu\r\n", buffer[i]);
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
						mgmtvty_process_key(c, buffer[i]);

					default:
						msg_type = 0;
						continue;
				}
				break;

			case 2: // Handle escape sequence
				if (i + 1 > len || buffer[i] != '[') {
					pom_log(POM_LOG_WARN "Invalid escape sequence\r\n");
					msg_type = 0;
					break;
				}
				i++;
				switch (buffer[i]) {
					case '3': // delete (complete escape seq is 0x3 0x7e)
						i++;
						// same as Ctrl-D if there is something in the buffer
						if (strlen(c->cmds[c->curcmd]) > 0)
							mgmtvty_process_key(c, 0x4);
						break;
						
					case 'A': { // up arrow
							int prev = c->curcmd - 1;
							if (prev < 0)
								prev = MGMT_CMD_HISTORY_SIZE - 1;

							if (!c->cmds[prev])
								break;

							int i;
							for (i = c->cursor_pos; i > 0; i--)
								mgmtsrv_send(c, "\b");
							for (i = 0; i < strlen(c->cmds[c->curcmd]); i++)
								mgmtsrv_send(c, " ");
							for (i = 0; i < strlen(c->cmds[c->curcmd]); i++)
								mgmtsrv_send(c, "\b");
							c->curcmd = prev;

							mgmtsrv_send(c, c->cmds[c->curcmd]);
							c->cursor_pos = strlen(c->cmds[c->curcmd]);

							break;
						}
					case 'B': { // down arrow
							int next = c->curcmd + 1;
							if (next >= MGMT_CMD_HISTORY_SIZE)
								next = 0;

							if (!c->cmds[next])
								break;

							int i;
							for (i = c->cursor_pos; i > 0; i--)
								mgmtsrv_send(c, "\b");
							for (i = 0; i < strlen(c->cmds[c->curcmd]); i++)
								mgmtsrv_send(c, " ");
							for (i = 0; i < strlen(c->cmds[c->curcmd]); i++)
								mgmtsrv_send(c, "\b");
							c->curcmd = next;

							mgmtsrv_send(c, c->cmds[c->curcmd]);
							c->cursor_pos = strlen(c->cmds[c->curcmd]);

							break;
						}
					case 'C': // right arrow
						if (c->cursor_pos < strlen(c->cmds[c->curcmd])) {
							char chr[2];
							chr[0] = c->cmds[c->curcmd][c->cursor_pos];
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
					case 'F': // end
						// same as Ctrl-E
						mgmtvty_process_key(c, 0x5);
						break;
					case 'H': // home
						//sameas Ctr-A
						mgmtvty_process_key(c, 0x1);
						break;
					default: // not handled
						pom_log(POM_LOG_TSHOOT "Unknown escape sequence pressed : %c\r\n", buffer[i]);
						
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
				mgmtvty_process_key(c, buffer[i]);
		}


	}

	return POM_OK;

}


int mgmtvty_process_telnet_option(struct mgmt_connection *c, unsigned char *opt, unsigned int len) {

#ifdef DEBUG

	if (opt[0] == SB) {
		pom_log(POM_LOG_TSHOOT "Got telnet suboption %s\r\n", TELOPT(opt[1]));
	} else {

		pom_log(POM_LOG_TSHOOT "Got telnet option %s %s\r\n", TELCMD(opt[0]), TELOPT(opt[1]));
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
					pom_log(POM_LOG_TSHOOT "New remote window size for connection %u is %ux%u\r\n", c->fd, c->win_x, c->win_y);
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
					return POM_OK;

			}
			send(c->fd, deny_msg, 3, 0);

		}
	}


	return POM_OK;

}

int mgmtvty_completion(struct mgmt_connection *c, unsigned char key) {

	// Let's start by splitting this line
	char *words[MGMT_MAX_CMD_WORDS_ARGS];
	unsigned int words_count = 0, i;
	char *str, *saveptr = NULL, *token;

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


	struct mgmt_command *start, *end;
	mgmtsrv_match_command(words, &start, &end);
	free(tmpcmdstr);

	if (!start)
		return POM_OK;

	if (key == '?' || (key == '\t' && c->cmds[c->curcmd][strlen(c->cmds[c->curcmd]) - 1] == ' ')) {
		int word = words_count - 1;
		struct mgmt_command *cur = start;
		if (c->cmds[c->curcmd][strlen(c->cmds[c->curcmd]) - 1] == ' ') {
			// first check all the previous words are the same
			while (cur && cur->prev != end) {
				for (i = 0; i < words_count; i++)
					if (!cur->words[i] || !start->words[i] || strcmp(cur->words[i], start->words[i]))
						return POM_OK;
				cur = cur->next;
			}
			word = words_count;
			cur = start;
		}

		if (!start->words[word]) // there is no more word
			return POM_OK;

		mgmtsrv_send(c, "\r\n%s ", start->words[word]);
		while (start && start->prev != end) {
			if (cur->words[word] && start->words[word] && strcmp(cur->words[word], start->words[word])) {
				cur = start;
				mgmtsrv_send(c, "%s ", cur->words[word]);
			}
			start = start->next;
		}

		mgmtsrv_send(c, "\r\n" MGMT_CMD_PROMPT "%s", c->cmds[c->curcmd]);
		c->cursor_pos = strlen(c->cmds[c->curcmd]);

	} else if (key == '\t') {
		struct mgmt_command *cur = start;
		// first check all the previous words are the same
		while (cur && cur->prev != end) {
			for (i = 0; i < words_count; i++)
				if (!cur->words[i] || !start->words[i] ||  strcmp(cur->words[i], start->words[i]))
					return POM_OK;
			cur = cur->next;
		}

		// compute len of last word we got already
		int pos = strlen(c->cmds[c->curcmd]) - 1;
		int len = 0;
		while (pos >= 0 && c->cmds[c->curcmd][pos] != ' ') {
			len++;
			pos--;
		}
		
		c->cmds[c->curcmd] = realloc(c->cmds[c->curcmd], strlen(c->cmds[c->curcmd]) + strlen(start->words[words_count - 1] + len) + 2);
		strcat(c->cmds[c->curcmd], start->words[words_count - 1] + len);
		strcat(c->cmds[c->curcmd], " ");
		mgmtsrv_send(c, "%s ", start->words[words_count - 1] + len);
		c->cursor_pos = strlen(c->cmds[c->curcmd]);

	} else
		return POM_ERR;


	return POM_OK;

}

int mgmtvty_process_key(struct mgmt_connection *c, unsigned char key) {

	switch (key) {
		case 0: // ignore this one
			break;

		case 0x1: { // Ctrl-A
			while (c->cursor_pos > 0) {
				mgmtsrv_send(c, "\b");
				c->cursor_pos--;
			}
			break;
		}

		case 0x2: { // Ctrl-B
			if (c->cursor_pos > 0) {
				mgmtsrv_send(c, "\b");
				c->cursor_pos--;
			}
			break;
		}

		case 0x3: { // Ctrl-C
			mgmtsrv_send(c, "\r\n" MGMT_CMD_PROMPT);
			c->cmds[c->curcmd] = realloc(c->cmds[c->curcmd], 1);
			c->cmds[c->curcmd][0] = 0;
			c->cursor_pos = 0;
			break;
		}

		case 0x4: { // Ctrl-D
			if (strlen(c->cmds[c->curcmd]) == 0)
				mgmtcmd_exit(c, 0, NULL);
			else {
				size_t cmdlen = strlen(c->cmds[c->curcmd]);
				if (c->cursor_pos < cmdlen) {
					memmove(c->cmds[c->curcmd] + c->cursor_pos, c->cmds[c->curcmd] + c->cursor_pos + 1, cmdlen - c->cursor_pos);
					c->cmds[c->curcmd] = realloc(c->cmds[c->curcmd], cmdlen);
					mgmtsrv_send(c, c->cmds[c->curcmd] + c->cursor_pos);
					mgmtsrv_send(c, " ");
					int i;
					for (i = strlen(c->cmds[c->curcmd]); i >= c->cursor_pos; i--)
						mgmtsrv_send(c, "\b");

				}
			
			}
			break;
		}

		case 0x5: { // Ctrl-E
			while (c->cursor_pos < strlen(c->cmds[c->curcmd])) {
				mgmtsrv_send(c, c->cmds[c->curcmd] + c->cursor_pos);
				c->cursor_pos = strlen(c->cmds[c->curcmd]);
			}
			break;
		}

		case 0x7F:
		case '\b': { // backspace
			size_t cmdlen = strlen(c->cmds[c->curcmd]);
			if (cmdlen == 0 || c->cursor_pos == 0)
				break;

			c->cursor_pos--;

			memmove(c->cmds[c->curcmd] + c->cursor_pos, c->cmds[c->curcmd] + c->cursor_pos + 1, cmdlen - c->cursor_pos);
			c->cmds[c->curcmd][cmdlen - 1] = 0;
			c->cmds[c->curcmd] = realloc(c->cmds[c->curcmd], cmdlen);
			mgmtsrv_send(c, "\b");
			mgmtsrv_send(c, c->cmds[c->curcmd] + c->cursor_pos);
			mgmtsrv_send(c, " ");
			int i;
			for (i = c->cursor_pos; i < cmdlen; i++)
				mgmtsrv_send(c, "\b");

			break;
		}

		case 0x15: { // Ctrl-U
			int i;
			size_t cmdlen = strlen(c->cmds[c->curcmd]);
			for (i = c->cursor_pos; i > 0; i--)
				mgmtsrv_send(c, "\b");
			for (i = 0; i < cmdlen; i++)
				mgmtsrv_send(c, " ");
			for (i = 0; i < cmdlen; i++)
				mgmtsrv_send(c, "\b");
			c->cmds[c->curcmd] = realloc(c->cmds[c->curcmd], 1);
			c->cmds[c->curcmd][0] = 0;
			c->cursor_pos = 0;
			break;
		}

		case '\r': { // carriage return
			if (c->state == MGMT_STATE_PASSWORD) {
				if (!mgmtsrv_get_password() || !strcmp(c->cmds[c->curcmd], mgmtsrv_get_password())) {
					c->state = MGMT_STATE_AUTHED;
					mgmtsrv_send(c, "\r\n" MGMT_CMD_PROMPT);
				} else {
					// Need this to actualy send something in the vty
					c->state = MGMT_STATE_INIT;

					if (c->auth_tries >= 2) {
						mgmtsrv_send(c, "\r\nToo many authentication failure.\r\n");
						mgmtsrv_close_connection(c);
						break;
					}
					mgmtsrv_send(c, "\r\n" MGMT_CMD_PWD_PROMPT);
					c->state = MGMT_STATE_PASSWORD;
					c->auth_tries++;
				}
				c->cmds[c->curcmd] = realloc(c->cmds[c->curcmd], 1);
				c->cmds[c->curcmd][0] = 0;
				c->cursor_pos = 0;
				break;

			}

			if (strlen(c->cmds[c->curcmd]) == 0) {
				mgmtsrv_send(c, "\r\n" MGMT_CMD_PROMPT);
				break;
			}

			unsigned int curcmd = c->curcmd;
			
			// Alloc the next one
			c->curcmd++;
			if (c->curcmd >= MGMT_CMD_HISTORY_SIZE)
				c->curcmd = 0;
			c->cmds[c->curcmd] = realloc(c->cmds[c->curcmd], 1);
			c->cmds[c->curcmd][0] = 0;
			c->cursor_pos = 0;

			// Make sure the one that comes after is empty
			int next = c->curcmd + 1;
			if (next >= MGMT_CMD_HISTORY_SIZE)
				next = 0;
			if (c->cmds[next]) {
				free(c->cmds[next]);
				c->cmds[next] = 0;
			}

			// Process the command
			mgmtsrv_process_command(c, curcmd);
			mgmtsrv_send(c, "\r"MGMT_CMD_PROMPT);

			break;
		}

		case '\t': // tab completion
		case '?': { // completion
			if (strlen(c->cmds[c->curcmd]) > 0)
				mgmtvty_completion(c, key);

			break;
		}

		default: {
			size_t cmdlen = strlen(c->cmds[c->curcmd]) + 1;
			c->cmds[c->curcmd] = realloc(c->cmds[c->curcmd], cmdlen + 1);
			memmove(c->cmds[c->curcmd] + c->cursor_pos + 1, c->cmds[c->curcmd] + c->cursor_pos, cmdlen - c->cursor_pos);
			c->cmds[c->curcmd][c->cursor_pos] = key;
			mgmtsrv_send(c, c->cmds[c->curcmd] + c->cursor_pos);
			int i;
			for (i = cmdlen - 1; i > c->cursor_pos; i--)
				mgmtsrv_send(c, "\b");
			c->cursor_pos++;
		}

	}


	return POM_OK;

}

int mgmtvty_print_usage(struct mgmt_connection *c, struct mgmt_command *cmd) {

	mgmtsrv_send(c, "Usage : ");
	if (cmd->usage) {
		mgmtsrv_send(c, cmd->usage);
	} else {
		int i;
		for (i = 0; i < MGMT_MAX_CMD_WORDS && cmd->words[i]; i++) {
			mgmtsrv_send(c, cmd->words[i]);
			mgmtsrv_send(c, " ");
		}
			


	}
	mgmtsrv_send(c, "\r\n");
	return POM_OK;
}
