/*
 *  packet-o-matic : modular network traffic processor
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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

#define WAIT_CONNS 2

#include <signal.h>

#include "common.h"
#include "xmlrpcsrv.h"
#include "xmlrpccmd.h"

struct xmlrpc_connection *sockets_head;

TServer abyssServer;
xmlrpc_registry * registryP;

char *xmlrpc_password = NULL;

#ifdef XMLRPC_IPV6
void socketGetPeerName(const TSocket *socketP, TIPAddr *ipAddrP, uint16_t *portNumberP, abyss_bool *successP) {


	socklen_t addrlen;
	int rc;
	struct sockaddr sockAddr;

	addrlen = sizeof(sockAddr);

	struct socketS *socketStruct = socketP->implP;
	rc = getpeername(socketStruct->fd, &sockAddr, &addrlen);

	if (rc < 0) {
		*successP = FALSE;
	} else {
		*successP = FALSE;
		if (sockAddr.sa_family == AF_INET) {
			const struct sockaddr_in *sockAddrInP = (struct sockaddr_in *) &sockAddr;
			*ipAddrP = sockAddrInP->sin_addr;
			*portNumberP = sockAddrInP->sin_port;
			*successP = TRUE;

		} else if (sockAddr.sa_family == AF_INET6) {
			const struct sockaddr_in6 *sockAddrIn6P = (struct sockaddr_in6 *) &sockAddr;
			ipAddrP->s_addr = 0;
			*portNumberP = sockAddrIn6P->sin6_port;
			*successP = TRUE;
		} else
			*successP = FALSE;
	}

}

#endif

int xmlrpcsrv_init(const char *port) {
	
	// first of all, ignore SIGPIPE
	signal(SIGPIPE, SIG_IGN);


	// init various variables
	sockets_head = NULL;
	registryP = NULL;

	// open sockets

	char errbuff[256];
	int sockfd = -1;

	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(NULL, port, &hints, &res) < 0) {
		strerror_r(errno, errbuff, 256);
		pom_log(POM_LOG_ERR "Error while finding an address to listen on : %s\r\n", errbuff);
		return POM_ERR;
	}

	struct addrinfo *tmpres = res;
	while (tmpres) {

#ifndef XMLRPC_IPV6
		// xmlrpc-c doesn't really support ipv6 yet
		if (tmpres->ai_family == AF_INET6) {
			tmpres = tmpres->ai_next;
			continue;
		}
#endif


		if (tmpres->ai_family != AF_INET && tmpres->ai_family != AF_INET6) {
			tmpres = tmpres->ai_next;
			continue;
		}
 
		char host[NI_MAXHOST], port[NI_MAXSERV];
		memset(host, 0, NI_MAXHOST);
		memset(port, 0, NI_MAXSERV);

		getnameinfo((struct sockaddr*)tmpres->ai_addr, tmpres->ai_addrlen, host, NI_MAXHOST, port, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);

		sockfd = socket(tmpres->ai_family, tmpres->ai_socktype, tmpres->ai_protocol);
		if (sockfd < 0) {
			strerror_r(errno, errbuff, 256);
			pom_log(POM_LOG_ERR "Error while creating socket : %s\r\n", errbuff);
			tmpres = tmpres->ai_next;
			continue;
		}

		const int yes = 1;
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			strerror_r(errno, errbuff, 256);
			pom_log(POM_LOG_WARN "Error while setting REUSEADDR option on socket : %s\r\n", errbuff);
			close(sockfd);
			tmpres = tmpres->ai_next;
			continue;
		}

		if (bind(sockfd, tmpres->ai_addr, tmpres->ai_addrlen) < 0) {
			int my_errno = errno;
			if (! (my_errno == EADDRINUSE && sockets_head)) { // Do not show an error in case we did bind already
				strerror_r(my_errno, errbuff, 256);
				pom_log(POM_LOG_ERR "Error while binding socket on address %s : %s\r\n", host, errbuff);
			}
			close(sockfd);
			tmpres = tmpres->ai_next;
			continue;
		}

		if (listen(sockfd, WAIT_CONNS)) {
			strerror_r(errno, errbuff, 256);
			pom_log(POM_LOG_ERR "Error while switching socket to listen state : %s\r\n", errbuff);
			close(sockfd);
			tmpres = tmpres->ai_next;
			continue;
		}

		pom_log("XML-RPC server listening on %s:%s\r\n", host, port);

		struct xmlrpc_connection *tmp = malloc(sizeof(struct xmlrpc_connection));
		memset(tmp, 0, sizeof(struct xmlrpc_connection));

		tmp->fd = sockfd;
		tmp->next = sockets_head;
		sockets_head = tmp;

		tmpres = tmpres->ai_next;
	}

	freeaddrinfo(res);

	if (!sockets_head) {
		pom_log(POM_LOG_ERR "Could not open a single socket\r\n");
		return POM_ERR;
	}


	// Create the abyss server


	xmlrpc_env env;
	xmlrpc_env_init(&env);
	registryP = xmlrpc_registry_new(&env);

	if (env.fault_occurred) {
		xmlrpc_env_clean(&env);
		return POM_ERR;
	}

	ServerCreateNoAccept(&abyssServer, "PacketOMaticXmlRpcServer", NULL, NULL);

	// setup default xmlrpc-c handlers
	xmlrpc_server_abyss_set_handlers2(&abyssServer, XMLRPC_URI, registryP);

	// setup authentication handler
	struct URIHandler2 authHandler;
	memset(&authHandler, 0, sizeof(struct URIHandler2));
	authHandler.handleReq2 = xmlrpcsrv_authentication_handler2;
	abyss_bool succeeded;
	ServerAddHandler2(&abyssServer, &authHandler, &succeeded);

	// setup the default handler
	ServerDefaultHandler(&abyssServer, xmlrpcsrv_default_handler);

	xmlrpc_env_clean(&env);

	// register all the commands
	xmlrpccmd_register_all();

	return POM_OK;
}

int xmlrpcsrv_process() {

	fd_set fds;

	FD_ZERO(&fds);
	int max_fd = 0;

	struct xmlrpc_connection *cc = sockets_head;
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
		return POM_OK;

	cc = sockets_head;
	while(cc) {

		if (FD_ISSET(cc->fd, &fds)) {
			xmlrpcsrv_process_connection(cc);
		}
		cc = cc->next;
	}

	return POM_OK;

}

int xmlrpcsrv_process_connection(struct xmlrpc_connection *c) {


	struct sockaddr_storage remote_addr;
	socklen_t remote_addr_len = sizeof(struct sockaddr_storage);

	int sockfd = -1;
	sockfd = accept(c->fd, (struct sockaddr *) &remote_addr, &remote_addr_len);

	if (sockfd < 0) {
		pom_log(POM_LOG_ERR "Error while accepting new connection\r\n");
		return POM_ERR;
	}


	char host[NI_MAXHOST], port[NI_MAXSERV];
	memset(host, 0, NI_MAXHOST);
	memset(port, 0, NI_MAXSERV);

	getnameinfo((struct sockaddr*)&remote_addr, remote_addr_len, host, NI_MAXHOST, port, NI_MAXSERV, NI_NUMERICHOST);

	pom_log(POM_LOG_DEBUG "Accepted XML-RPC connection from %s on socket %u\r\n", host, sockfd);

	TSocket * socketP;
	char * error;
	int res = POM_OK;


	SocketUnixCreateFd(sockfd, &socketP);
#ifdef XMLRPC_IPV6
	socketP->vtbl.getPeerName = socketGetPeerName;
#endif
	ServerRunConn2(&abyssServer, socketP, (const char **) &error);
	if (error) {
		pom_log(POM_LOG_ERR "Couldn't run the XML-RPC server : %s\r\n", error);
		free(error);
		res = POM_ERR;
	}

	SocketDestroy(socketP);
	close(sockfd);
	return POM_OK;

}


int xmlrpcsrv_register_command(struct xmlrpc_command *cmd) {

	if (!registryP)
		return POM_ERR;

	xmlrpc_env env;
	xmlrpc_env_init(&env);

	xmlrpc_registry_add_method_w_doc(&env, registryP, NULL, cmd->name, cmd->callback_func, NULL, cmd->signature, cmd->help);
	if (env.fault_occurred) {
		xmlrpc_env_clean(&env);
		return POM_ERR;
	}
	xmlrpc_env_clean(&env);

	return POM_OK;

}

int xmlrpcsrv_set_password(const char *password) {
	
	if (xmlrpc_password)
		free(xmlrpc_password);

	if (!password) {
		xmlrpc_password = NULL;
		return POM_OK;
	}

	xmlrpc_password = malloc(strlen(password) + 1);
	strcpy(xmlrpc_password, password);

	return POM_OK;
}

int xmlrpcsrv_cleanup() {

	if (registryP)
		xmlrpc_registry_free(registryP);
	
	registryP = NULL;

	if (sockets_head)
		ServerFree(&abyssServer);

	while (sockets_head) {
		struct xmlrpc_connection *tmp = sockets_head->next;
		close(sockets_head->fd);
		free(sockets_head);
		sockets_head = tmp;
	}

	return POM_OK;
}

void xmlrpcsrv_authentication_handler2(struct URIHandler2 *handler, TSession *sessionP, abyss_bool *successP) {

	if (!xmlrpc_password) { // no password defined
		*successP = FALSE;
		return;
	}

	const TRequestInfo *requestInfoP;
	SessionGetRequestInfo(sessionP, &requestInfoP);

	if (strcmp(requestInfoP->uri, XMLRPC_URI)) {
		*successP = FALSE;
		return;
	}
		


	char *hdr = RequestHeaderValue(sessionP, "authorization");

	if (hdr) {
		while (*hdr && *hdr == ' ')
			hdr++;
		if (!strncasecmp(hdr, "basic", strlen("basic"))) {
			hdr = strchr(hdr, ' ' );
			while (*hdr && *hdr == ' ')
				hdr++;

			if (hdr) {
			


				char *user = "admin";

				char *credentials = malloc(strlen(user) + strlen(":") + strlen(xmlrpc_password) + 3);
				strcpy(credentials, user);
				strcat(credentials, ":");
				strcat(credentials, xmlrpc_password);

				xmlrpc_env env;
				xmlrpc_env_init(&env);
				xmlrpc_mem_block *enc_credentials;
				enc_credentials = xmlrpc_base64_encode_without_newlines(&env, (unsigned char *) credentials, strlen(credentials));
				free(credentials);

				if (!env.fault_occurred) {
					
					// add null at the end of encoded string
					char null = 0;
					xmlrpc_mem_block_append(&env, enc_credentials, &null, 1);

					if (!strcmp(hdr, xmlrpc_mem_block_contents(enc_credentials))) {
						*successP = FALSE; // FALSE means hunt to the next handler
						xmlrpc_mem_block_free(enc_credentials);
						xmlrpc_env_clean(&env);
						return;
					}

					xmlrpc_mem_block_free(enc_credentials);
				}
				xmlrpc_env_clean(&env);
			}

		}
	}

	
	ResponseAddField(sessionP, "WWW-Authenticate", "Basic realm=\"" XMLRPC_REALM "\"");
	ResponseStatus(sessionP, 401);

	*successP = TRUE;

}


abyss_bool xmlrpcsrv_default_handler(TSession * const sessionP) {

	char *response = "<html><head><title>Packet-o-matic XML-RPC interface</title></head><body>See <a href=\"http://www.packet-o-matic.org\">http://www.packet-o-matic.org</a> for more info.</body></html>";

	ResponseWriteStart(sessionP);
	ResponseWriteBody(sessionP, response, strlen(response));
	return TRUE;
}

