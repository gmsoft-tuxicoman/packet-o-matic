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
#include "mgmtsrv.h"
#include "mgmtvty.h"
#include "mgmtcmd.h"

#define TELNET_SUBOPT_MAX 256

#define TELCMDS 1 // will populate the table telcmds
#define TELOPTS 1 // will populate the table telopts
#include <arpa/telnet.h>

int mgmtvty_init(struct mgmt_connection *c) {


	if (c->state != MGMT_STATE_INIT) {
		pom_log(POM_LOG_ERR "Error, connection in wrong state");
		return POM_ERR;
	}

	mgmtsrv_send(c, "\nThis is packet-o-matic " POM_VERSION "\nCopyright Guy Martin 2006-2008\n\n");

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
									pom_log(POM_LOG_WARN "Warning, unexpected value while reading telnet suboption : %hhu", buffer[i]);
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
				if (i + 1 > len || (buffer[i] != '[' && buffer[i] != 'O')) {
					pom_log(POM_LOG_WARN "Invalid escape sequence");
					msg_type = 0;
					break;
				}
				i++;
				switch (buffer[i]) {
					case '3': // delete (complete escape seq is 0x3 0x7e)
						i++;
						// same as Ctrl-D if there is something in the buffer
						if (strlen(c->curcmd) > 0)
							mgmtvty_process_key(c, 0x4);
						break;
					
					case 'A': { // up arrow
							int prev = c->history_pos - 1;
							if (prev < 0)
								prev = MGMT_CMD_HISTORY_SIZE - 1;

							if (!c->history[prev])
								break;

							if (!c->history[c->history_pos]) { // we move out of current command. save it
								c->history[c->history_pos] = malloc(strlen(c->curcmd) + 1);
								strcpy(c->history[c->history_pos], c->curcmd);

								// and make sure we still get a empty one
								int next = c->history_pos + 1;
								if (next >= MGMT_CMD_HISTORY_SIZE)
									next = 0;
								if (c->history[next]) {
									free(c->history[next]);
									c->history[next] = NULL;
								}


							}

							int i;
							for (i = 0; i < c->cursor_pos; i++)
								mgmtsrv_send(c, "\b");

							mgmtsrv_send(c, c->history[prev]);

							int lendiff = strlen(c->curcmd) - strlen(c->history[prev]);
							if (lendiff > 0) {
								for (i = 0; i < lendiff; i++)
									mgmtsrv_send(c, " ");
								for (i = 0; i < lendiff; i++)
									mgmtsrv_send(c, "\b");
							}

							c->history_pos = prev;

							c->curcmd = realloc(c->curcmd, strlen(c->history[c->history_pos]) + 1);
							strcpy(c->curcmd, c->history[c->history_pos]);
							c->cursor_pos = strlen(c->curcmd);

							break;
						}
					case 'B': { // down arrow
							int next = c->history_pos + 1;
							if (next >= MGMT_CMD_HISTORY_SIZE)
								next = 0;

							if (!c->history[next])
								break;


							int i;
							for (i = 0; i < c->cursor_pos; i++)
								mgmtsrv_send(c, "\b");

							mgmtsrv_send(c, c->history[next]);

							int lendiff = strlen(c->curcmd) - strlen(c->history[next]);
							if (lendiff > 0) {
								for (i = 0; i < lendiff; i++)
									mgmtsrv_send(c, " ");
								for (i = 0; i < lendiff; i++)
									mgmtsrv_send(c, "\b");
							}

							c->history_pos = next;

							c->curcmd = realloc(c->curcmd, strlen(c->history[c->history_pos]) + 1);
							strcpy(c->curcmd, c->history[c->history_pos]);

							c->cursor_pos = strlen(c->curcmd);

							break;
						}
					case 'C': // right arrow
						if (c->cursor_pos < strlen(c->curcmd)) {
							char chr[2];
							chr[0] = c->curcmd[c->cursor_pos];
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
					case '4':
						i++; // ignore following ~
					case 'F': // end
						// same as Ctrl-E
						mgmtvty_process_key(c, 0x5);
						break;
					case '1':
						i++; // ignore following ~
					case 'H': // home
						//sameas Ctr-A
						mgmtvty_process_key(c, 0x1);
						break;
					case '2':
					case '5':
					case '6':
						i++; // ignore following ~
						break;
					default: // not handled
						pom_log(POM_LOG_TSHOOT "Unknown escape sequence pressed : %c", buffer[i]);
						
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
		pom_log(POM_LOG_TSHOOT "Got telnet suboption %s", TELOPT(opt[1]));
	} else {

		pom_log(POM_LOG_TSHOOT "Got telnet option %s %s", TELCMD(opt[0]), TELOPT(opt[1]));
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
					pom_log(POM_LOG_TSHOOT "New remote window size for connection %u is %ux%u", c->fd, c->win_x, c->win_y);
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

	// Use temporary buffer to avoid modifying the current command
	char *tmpcmdstr = malloc(strlen(c->curcmd) + 1);
	strcpy(tmpcmdstr, c->curcmd);

	for (str = tmpcmdstr; ;str = NULL) {
		if (words_count >= MGMT_MAX_CMD_WORDS_ARGS) {
			mgmtsrv_send(c, "\r\nToo many arguments\r\n" MGMT_CMD_PROMPT "%s", c->curcmd);
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

	if (strlen(c->curcmd) > 0 && c->curcmd[strlen(c->curcmd) - 1] != ' ')
		words_count--; // we have to deal with the currently being typed word


	struct mgmt_command *start, *end;
	mgmtsrv_match_command(words, &start, &end);

	if (!start) {
		free(tmpcmdstr);
		return POM_OK;
	}


	if (key == '?') {
		mgmtsrv_send(c, "\r\n");
		mgmtcmd_print_help(c, start, end);
		mgmtsrv_send(c, MGMT_CMD_PROMPT "%s", c->curcmd);

	} else if (key == '\t') {
		// compute the amount of possible matches
		struct mgmt_command *cur = start;
		struct mgmt_command_arg *list = NULL;

		while (cur && cur->prev != end) {
			
			if (!cur->words[words_count]) {
				struct mgmt_command_arg *items = NULL;
				if (cur->completion)
					items = cur->completion(words_count, words);
				if (items) {
					struct mgmt_command_arg *tmp;
					for (tmp = items; tmp->next; tmp = tmp->next);
					tmp->next = list; list = items;
				}

			} else {
				struct mgmt_command_arg *item = malloc(sizeof(struct mgmt_command_arg));
				memset(item, 0, sizeof(struct mgmt_command_arg));
				item->word = malloc(strlen(cur->words[words_count]) + 1);
				strcpy(item->word, cur->words[words_count]);
				item->next = list;
				list = item;
	
			}
			cur = cur->next;
		}

		if (list) {

			int swapped = 0;
			do {
				struct mgmt_command_arg* item = list;
				swapped = 0;
				while (item->next) {
					int j;
					if (!strcmp(item->word, item->next->word)) {
						struct mgmt_command_arg *tmp = item->next;
						item->next = item->next->next;
						free(tmp->word);
						free(tmp);
						continue;
					}
					for (j = 0; item->word[j] && item->next->word[j]; j++) {
						if (j > 0 && item->word[j - 1] != item->next->word[j - 1])
							break;
						if (item->word[j] > item->next->word[j]) {
							char *temp = item->word;
							item->word = item->next->word;
							item->next->word = temp;
							swapped = 1;
							break;
						}
					}
					item = item->next;
				}

			} while (swapped);
		
			if (!list->next) {
				if (words[words_count]) {
					int size = strlen(words[words_count]);
					int len = strlen(list->word) - size;
					c->curcmd = realloc(c->curcmd, strlen(c->curcmd) + len + 2);
					strcat(c->curcmd, list->word + size);
					strcat(c->curcmd, " ");
					mgmtsrv_send(c, "%s ", list->word + size);
					c->cursor_pos = strlen(c->curcmd);
				} else {
					c->curcmd = realloc(c->curcmd, strlen(c->curcmd) + strlen(list->word) + 2);
					strcat(c->curcmd, list->word);
					strcat(c->curcmd, " ");
					mgmtsrv_send(c, "%s ", list->word);
					c->cursor_pos = strlen(c->curcmd);
				}
				
			} else {
				mgmtsrv_send(c, "\r\n");
				struct mgmt_command_arg *tmp = list;
				while (tmp) {
					mgmtsrv_send(c, "%s ", tmp->word);
					tmp = tmp->next;
				}
				mgmtsrv_send(c, "\r\n" MGMT_CMD_PROMPT "%s", c->curcmd);
			}

			struct mgmt_command_arg *item = list;
			while (item) {
				free(item->word);
				struct mgmt_command_arg *tmp = item;
				item = item->next;
				free(tmp);
			}

			free(tmpcmdstr);
			return POM_OK;
		
		}
	}

	free(tmpcmdstr);
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
			c->curcmd = realloc(c->curcmd, 1);
			*c->curcmd = 0;
			c->cursor_pos = 0;

			if (c->history[c->history_pos]) { // history position moved. we need to free last entry
				int last;
				while (c->history[c->history_pos]) {
					last = c->history_pos;
					c->history_pos++;
					if (c->history_pos >= MGMT_CMD_HISTORY_SIZE)
						c->history_pos = 0;
				}
				free(c->history[last]);
				c->history[last] = NULL;
				c->history_pos = last;

			}

			break;
		}

		case 0x4: { // Ctrl-D
			if (strlen(c->curcmd) == 0)
				mgmtcmd_exit(c, 0, NULL);
			else {
				size_t cmdlen = strlen(c->curcmd);
				if (c->cursor_pos < cmdlen) {
					memmove(c->curcmd + c->cursor_pos, c->curcmd + c->cursor_pos + 1, cmdlen - c->cursor_pos);
					c->curcmd = realloc(c->curcmd, cmdlen);
					mgmtsrv_send(c, c->curcmd + c->cursor_pos);
					mgmtsrv_send(c, " ");
					int i;
					for (i = strlen(c->curcmd); i >= c->cursor_pos; i--)
						mgmtsrv_send(c, "\b");

				}
			
			}
			break;
		}

		case 0x5: { // Ctrl-E
			while (c->cursor_pos < strlen(c->curcmd)) {
				mgmtsrv_send(c, c->curcmd + c->cursor_pos);
				c->cursor_pos = strlen(c->curcmd);
			}
			break;
		}

		case 0x7F:
		case '\b': { // backspace
			size_t cmdlen = strlen(c->curcmd);
			if (cmdlen == 0 || c->cursor_pos == 0)
				break;

			c->cursor_pos--;

			memmove(c->curcmd + c->cursor_pos, c->curcmd + c->cursor_pos + 1, cmdlen - c->cursor_pos);
			c->curcmd[cmdlen - 1] = 0;
			c->curcmd = realloc(c->curcmd, cmdlen);
			mgmtsrv_send(c, "\b");
			mgmtsrv_send(c, c->curcmd + c->cursor_pos);
			mgmtsrv_send(c, " ");
			int i;
			for (i = c->cursor_pos; i < cmdlen; i++)
				mgmtsrv_send(c, "\b");

			break;
		}

		case 0x0C: { // Ctrl-L
			mgmtsrv_send(c, "\033c" MGMT_CMD_PROMPT);
			mgmtsrv_send(c, c->curcmd);
			int pos = strlen(c->curcmd) - c->cursor_pos;
			for (; pos > 0; pos--)
				mgmtsrv_send(c, "\b");
			break;
		}

		case 0x15: { // Ctrl-U
			int i;
			size_t cmdlen = strlen(c->curcmd);
			for (i = c->cursor_pos; i > 0; i--)
				mgmtsrv_send(c, "\b");
			for (i = 0; i < cmdlen; i++)
				mgmtsrv_send(c, " ");
			for (i = 0; i < cmdlen; i++)
				mgmtsrv_send(c, "\b");
			c->curcmd = realloc(c->curcmd, 1);
			c->curcmd[0] = 0;
			c->cursor_pos = 0;
			break;
		}

		case '\r': { // carriage return
			if (c->state == MGMT_STATE_PASSWORD) {
				if (!mgmtsrv_get_password() || !strcmp(c->curcmd, mgmtsrv_get_password())) {
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
				c->curcmd = realloc(c->curcmd, 1);
				c->curcmd[0] = 0;
				c->cursor_pos = 0;
				break;

			}

			if (strlen(c->curcmd) == 0) {
				mgmtsrv_send(c, "\r\n" MGMT_CMD_PROMPT);
				break;
			}
	
			if (c->history[c->history_pos]) { // history position moved. we need to reuse last entry
				int last;
				while (c->history[c->history_pos]) {
					last = c->history_pos;
					c->history_pos++;
					if (c->history_pos >= MGMT_CMD_HISTORY_SIZE)
						c->history_pos = 0;
				}
				c->history_pos = last;
			}
			
			c->history[c->history_pos] = realloc(c->history[c->history_pos], strlen(c->curcmd) + 1);
			strcpy(c->history[c->history_pos], c->curcmd);
			c->history_pos++;
			if (c->history_pos >= MGMT_CMD_HISTORY_SIZE)
				c->history_pos = 0;

			if (c->history[c->history_pos]) {
				free(c->history[c->history_pos]);
				c->history[c->history_pos] = NULL;
			}

			// Process the command
			mgmtsrv_process_command(c);
			c->cursor_pos = 0;
			c->curcmd = realloc(c->curcmd, 1);
			*c->curcmd = 0;
			mgmtsrv_send(c, "\r" MGMT_CMD_PROMPT);

			break;
		}

		case '\t': // tab completion
		case '?': { // completion
			mgmtvty_completion(c, key);
			break;
		}

		default: {

			if (key < 0x20 || (key > 0x7F && key < 0xA0)) // Trim non printable chars
				break;

			size_t cmdlen = strlen(c->curcmd) + 1;
			c->curcmd = realloc(c->curcmd, cmdlen + 1);
			memmove(c->curcmd + c->cursor_pos + 1, c->curcmd + c->cursor_pos, cmdlen - c->cursor_pos);
			c->curcmd[c->cursor_pos] = key;
			mgmtsrv_send(c, c->curcmd + c->cursor_pos);
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
