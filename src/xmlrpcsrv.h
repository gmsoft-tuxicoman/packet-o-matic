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


#ifndef __XMLRPCSRV_H__
#define __XMLRPCSRV_H__

#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <errno.h>



#include <xmlrpc-c/base.h>
#include <xmlrpc-c/abyss.h>
#include <xmlrpc-c/server.h>
#include <xmlrpc-c/server_abyss.h>


#define XMLRPC_URI "/RPC2"
#define XMLRPC_REALM "Packet-o-matic XML-RPC interface"
#define XMLRPC_READ_BLOCK_SIZE 2048


/*
 * Enable IPv6 for XML-RPC, right now it's just a hack.
 * If you do so, only request made using host name will work, no raw IPv6 address.
 * Abyss can't parse connection port if there are more than one semicolon.
 */
#define XMLRPC_IPV6


#ifdef XMLRPC_IPV6

struct socketS {
	int fd;
};

struct TSocketVtbl {
	void* destroy;
	void* write;
	void* read;
	void* connect;
	void* bind;
	void* listen;
	void* accept;
	void* error;
	void* wait;
	void* availableReadBytes;
	void* getPeerName;
};

struct _TSocket {
	unsigned int signature;
	void *implP;
	struct TSocketVtbl vtbl;
};

typedef struct in_addr TIPAddr;

void socketGetPeerName(const TSocket * socketP, TIPAddr *ipAddrP, uint16_t *portNumberP, abyss_bool *successP);


#endif

struct xmlrpc_connection {
	int fd; ///< fd of the socket
	int listening; ///< If it's a listening or active socket
	struct xmlrpc_connection *next; ///< Used for linking

};

struct xmlrpc_command {
	char *name;
	xmlrpc_value* (*callback_func) (xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
	char *signature;
	char *help;
};

int xmlrpcsrv_init(const char *port);
int xmlrpcsrv_process();
int xmlrpcsrv_process_connection(struct xmlrpc_connection *c);
int xmlrpcsrv_register_command(struct xmlrpc_command *cmd);
int xmlrpcsrv_set_password(const char *password);
int xmlrpcsrv_cleanup();

void xmlrpcsrv_authentication_handler2(struct URIHandler2 *handler, TSession *sessionP, abyss_bool *succeeded);
abyss_bool xmlrpcsrv_default_handler(TSession * const sessionP);

#endif

