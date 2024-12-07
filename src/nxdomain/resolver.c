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


#include "nxdomain.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#define MAXBUF (10 * 1024)

static uint16_t id = 0;

// timeout in seconds
// return 0 if domain OK
// return 1 if NXDOMAIN
// return 2 if timeout
int resolver(const char *domain, int timeout) {
	// init socket
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == -1)
		errExit("socket");
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(53);
	addr.sin_addr.s_addr = inet_addr(arg_server);
	socklen_t addr_len = sizeof(addr);

	// manufacture a dns query
	uint8_t dnsmsg_start[] = {
		0x00, 0x00,  // id
		0x01, 0x00, // flags
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};

	uint8_t dnsmsg[MAXBUF];
	int len = sizeof(dnsmsg_start);
	memcpy(dnsmsg, dnsmsg_start, len);
	id++;
	memcpy(dnsmsg, &id, sizeof(uint16_t));
	uint8_t *ptr = dnsmsg + len;
	*ptr++ = 0;
	strcpy((char *) ptr, domain);
	while(*ptr)
		ptr++;

	unsigned char cnt = 0;
	do {
		ptr--;
		if (*ptr != '.')
			cnt++;
		else {
			*ptr = cnt;
			cnt = 0;
		}
	}
	while (*ptr != 0);
	*ptr = cnt - 1;

	len++;
	while (*ptr != 0) {
		ptr++;
		len++;
	}
	ptr++;
//	len++;
	*ptr++ = 0;
	*ptr++ = 1;
	*ptr++ = 0;
	*ptr++ = 1;
	len += 4;

//dbg_memory(dnsmsg, len, "tx");

	// send query
	sendto(sock, dnsmsg, len, 0, (struct sockaddr *) &addr, addr_len);

	struct timeval t = { timeout, 0};	// 10 seconds timeout
	int retval = 0;
	while (1) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		int nfds = sock;
		nfds++;
		errno = 0;

		int rv = select(nfds, &fds, NULL, NULL, &t);
		if (rv == -1) {
			if (errno == EINTR) {
				// select() man page reads:
				// "... the sets and  timeout become undefined, so
				// do not rely on their contents after an error. "
				t.tv_sec = 10;
				t.tv_usec = 0;
				continue;
			}
			errExit("select");
		}
		if (rv == 0)	{ // timeout
			close(sock);
			return 2;
		}

		if (FD_ISSET(sock, &fds)) {
			uint8_t buf[MAXBUF];
			struct sockaddr_in remote;
			memset(&remote, 0, sizeof(remote));
			socklen_t remote_len = sizeof(struct sockaddr_in);
			ssize_t len = recvfrom(sock, buf, MAXBUF, 0, (struct sockaddr *) &remote, &remote_len);
			if (len != -1) { // todo: parse errno - EINTR
//dbg_memory(buf, len, "rx");
				if (memcmp(buf, &id, sizeof(uint16_t)) != 0) {
					fprintf(stderr, " old UDP packet ");
					fflush(0);
					continue;
				}

				// check for NXDOMAIN
				if ((buf[3] & 0x3) == 0x3) {
					fprintf(stderr, "N");
					fflush(0);
					retval = 1;
				}
			}
		}
		break;
	}
	close(sock);
	return retval;
}
