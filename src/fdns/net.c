/*
 * Copyright (C) 2019-2020 fdns Authors
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
#include <sys/un.h>
#include <ifaddrs.h>
#include <net/if.h>

// the number of bits in a network mask
static inline uint8_t mask2bits(uint32_t mask) {
	uint32_t tmp = 0x80000000;
	int i;
	uint8_t rv = 0;

	for (i = 0; i < 32; i++, tmp >>= 1) {
		if (tmp & mask)
			rv++;
		else
			break;
	}
	return rv;
}

void net_check_proxy_addr(const char *str) {
	if (arg_debug)
		printf("Checking proxy address %s\n", str);
	if (str == NULL || *str == '\0')
		goto errout;

	// simple addr check
	uint32_t ip;
	if (atoip(str, &ip))
		goto errout;

	// see if this address belongs to any local interface
	struct ifaddrs *ifaddr, *ifa;

	if (getifaddrs(&ifaddr) == -1)
		errExit("getifaddrs");

	int found = 0;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if (ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in *si = (struct sockaddr_in *) ifa->ifa_netmask;
			uint32_t ifmask = ntohl(si->sin_addr.s_addr);
			si = (struct sockaddr_in *) ifa->ifa_addr;
			uint32_t ifip = ntohl(si->sin_addr.s_addr);

			int status = 0;
			if (ifa->ifa_flags & IFF_RUNNING && ifa->ifa_flags & IFF_UP)
				status = 1;

			if (arg_debug)
				printf("Checking interface %s, %d.%d.%d.%d/%u\n",
				       ifa->ifa_name, PRINT_IP(ifip), mask2bits(ifmask));

			// is the address in the network range?
			if ((ip & ifmask) == (ifip & ifmask)) {
				found = 1;
				if (!status)
					logprintf("Warning: interface %s is down\n", ifa->ifa_name);
				break;
			}
		}
	}

	freeifaddrs(ifaddr);
	if (found)
		return;

	// exit with error using the code below
errout:
	fprintf(stderr, "Error: invalid proxy address\n");
	exit(1);
}



int net_local_dns_socket(void) {
	int slocal = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (slocal == -1)
		errExit("socket");

	int reuse = 1;
	if (setsockopt(slocal, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse)) < 0)
		errExit("setsockopt(SO_REUSEADDR)");

#ifdef SO_REUSEPORT
	if (setsockopt(slocal, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuse, sizeof(reuse)) < 0)
		errExit("setsockopt(SO_REUSEPORT)");
#endif

	// configure porxy server local  address:port
	struct sockaddr_in addr_local;
	memset(&addr_local, 0, sizeof(addr_local));
	addr_local.sin_family = AF_INET;
	char *tmp = (arg_proxy_addr) ? arg_proxy_addr : DEFAULT_PROXY_ADDR;
	addr_local.sin_addr.s_addr = inet_addr(tmp); //INADDR_LOOPBACK, INADDR_ANY
	if (arg_proxy_addr_any)
		addr_local.sin_addr.s_addr = INADDR_ANY;
	addr_local.sin_port = htons(53);

	int rv = bind(slocal, (struct sockaddr *) &addr_local, sizeof(addr_local));
	if (rv == -1)
		errExit("bind");

	return slocal;
}

int net_remote_dns_socket(struct sockaddr_in *addr, const char *ipstr) {
	// Remote dns server socket
	// this is the fallback server
	int sremote = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sremote == -1)
		errExit("socket");

	memset(addr, 0, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_port = htons(53);
	addr->sin_addr.s_addr = inet_addr(ipstr);

	return sremote;
}

void net_local_unix_socket(void) {
	// open a UNIX socket in order to alow only a  single fnds instance to run
	int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock == -1)
		errExit("socket");

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path + 1, UNIX_ADDRESS, strlen(UNIX_ADDRESS) + 1);

	int rv = bind(sock, (struct sockaddr *) &addr, sizeof(sa_family_t) + strlen(UNIX_ADDRESS) + 1); //sizeof(addr));
	if (rv == -1) {
		fprintf(stderr, "Error: only one fdns instance is allowed, shutting down...\n");
		exit(1);
	}
}
