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

	mgmtsrv_send(c, "\nThis is packet-o-matic. \nCopyright Guy Martin 2006-2007\n\n" MGMT_CMD_PROMPT);

	char commands[] = { IAC, WILL, TELOPT_ECHO, IAC, WILL, TELOPT_SGA, IAC, DO, TELOPT_NAWS, IAC, DONT, TELOPT_LINEMODE };
	send(c->fd, commands, sizeof(commands), 0);

	return MGMT_OK;

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
						mgmtvty_process_key(c, buffer[i]);

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
				mgmtvty_process_key(c, buffer[i]);
		}


	}

	return MGMT_OK;

}


int mgmtvty_process_telnet_option(struct mgmt_connection *c, unsigned char *opt, unsigned int len) {

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

int mgmtvty_process_key(struct mgmt_connection *c, unsigned char key) {

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
