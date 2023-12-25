/*
 * Copyright (C) 2019-2021 FDNS Authors
 *
 * This file is part of fdns project
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "fdns.h"
#include "timetrace.h"
#include <errno.h>

static DnsServer *fcurrent = NULL;	// current fallback server

static DnsServer fallback[] = {
	{ .name = "adguard", .address = "94.140.14.14"},	// adblock
	{ .name = "cleanbrowsing", .address = "185.228.168.9"},	// security
	{ .name = "cloudflare", .address = "1.1.1.2"},		// security
	{ .name = "nextdns", .address = "45.90.28.141" },	// security
	{ .name = "quad9", .address = "9.9.9.9"}		// security
};



DnsServer *server_fallback_get(void) {
	if (arg_fallback_server) {
		if (fcurrent == NULL) {
			fcurrent = malloc(sizeof(DnsServer));
			if (!fcurrent)
				errExit("malloc");
			memset(fcurrent, 0, sizeof(DnsServer));
			fcurrent->name = "custom";
			fcurrent->address = arg_fallback_server;
			printf("configuring fallback server %s\n", fcurrent->address);
		}
		return fcurrent;
	}

	if (fcurrent)
		return fcurrent;

	// init socket
	int i;
	int cnt = sizeof(fallback) / sizeof(DnsServer);
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
		errExit("socket");
	struct sockaddr_in addr_fallback[cnt];
	for (i = 0; i < cnt; i++) {
		memset(&addr_fallback[i], 0, sizeof(struct sockaddr_in));
		addr_fallback[i].sin_family = AF_INET;
		addr_fallback[i].sin_port = htons(53);
		addr_fallback[i].sin_addr.s_addr = inet_addr(fallback[i].address);
	}
	socklen_t addr_fallback_len = sizeof(addr_fallback[0]);

	// send example.com queries
	uint8_t dnsmsg[] = {
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f,
		0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
	};
	timetrace_start();
	// send to a random server
	sendto(sock, dnsmsg, sizeof(dnsmsg), 0, (struct sockaddr *) &addr_fallback[rand() % cnt], addr_fallback_len);
	// ... and to all of them just in case the random one didn't respond
	for (i = 0; i < cnt; i++)
		sendto(sock, dnsmsg, sizeof(dnsmsg), 0, (struct sockaddr *) &addr_fallback[i], addr_fallback_len);

	struct timeval t = { 1, 0};	// one second timeout
	while (1) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		int nfds = sock + 1;
		nfds++;
		errno = 0;

		int rv = select(nfds, &fds, NULL, NULL, &t);
		if (rv == -1) {
			if (errno == EINTR) {
				// select() man page reads:
				// "... the sets and  timeout become undefined, so
				// do not rely on their contents after an error. "
				t.tv_sec = 1;
				t.tv_usec = 0;
				continue;
			}
			errExit("select");
		}
		if (rv == 0)	// timeout
			break;

		if (FD_ISSET(sock, &fds)) {
			uint8_t buf[MAXBUF];
			float ms = timetrace_end();
			struct sockaddr_in remote;
			memset(&remote, 0, sizeof(remote));
			socklen_t remote_len = sizeof(struct sockaddr_in);
			ssize_t len = recvfrom(sock, buf, MAXBUF, 0, (struct sockaddr *) &remote, &remote_len);
			if (len != -1) { // todo: parse errno - EINTR
				for (i = 0; i < cnt; i++) {
					if (remote.sin_addr.s_addr == addr_fallback[i].sin_addr.s_addr) {
						printf("Testing fallback server: %s (%s) - %.02f ms\n", fallback[i].name, fallback[i].address, ms);
						fcurrent = &fallback[i];
						break;
					}
				}
			}
		}
		break;
	}

	close(sock);
	if (fcurrent == NULL) {
		fprintf(stderr, "Warning: fallback test failed, using Quad9 (9.9.9.9) server\n");
		fcurrent = &fallback[0];
	}

	return fcurrent;
}
