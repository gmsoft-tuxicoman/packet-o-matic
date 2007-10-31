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


#ifndef __MGMTVTY_H__
#define __MGMTVTY_H__

int mgmtvty_init(struct mgmt_connection *c);
int mgmtvty_process(struct mgmt_connection *c, unsigned char *buffer, unsigned int len);
int mgmtvty_process_telnet_option(struct mgmt_connection *c, unsigned char *opt, unsigned int len);
int mgmtvty_completion(struct mgmt_connection *c, unsigned char key);
int mgmtvty_process_key(struct mgmt_connection *c, unsigned char key);
int mgmtvty_print_usage(struct mgmt_connection *c, struct mgmt_command *cmd);

#endif

