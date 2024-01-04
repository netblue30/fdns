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
#include <errno.h>

Forwarder *fwd_list = NULL;
Forwarder *fwd_active = NULL;

void forwarder_set(const char *str) {
	assert(str);
	if (*str == '.')
		str++;
	if (*str == '\0') {
		fprintf(stderr, "Error: invalid forwarding domain\n");
		exit(1);
	}

	Forwarder *f = malloc(sizeof(Forwarder));
	if (!f)
		errExit("malloc");
	memset(f, 0, sizeof(Forwarder));

	// extract name
	f->name = strdup(str);
	if (!f->name)
		errExit("strdup");
	char *ptr = strchr(f->name, '@');
	if (!ptr || ptr == f->name) {
		fprintf(stderr, "Error: invalid forwarding %s\n", str);
		exit(1);
	}
	*ptr = '\0';
	f->name_len = strlen(f->name);

	// extract ip address
	ptr++;
	uint32_t ip;
	if (atoip(ptr, &ip)) {
		fprintf(stderr, "Error: invalid IP address %s\n", ptr);
		exit(1);
	}
	f->ip = ptr;

	// create socket
	f->sock = net_remote_dns_socket(&f->saddr, f->ip);
	f->slen = sizeof(f->saddr);
	if (arg_id == 0) {
		printf("forwarding \"%s\" to %s\n", f->name, f->ip);
		fflush(0);
	}

	f->next = fwd_list;
	fwd_list = f;
#ifdef HAVE_GCOV
	__gcov_flush();
#endif
}

// args: domain name and domain name length
// return 1 if found
int forwarder_check(const char *domain, unsigned len) {
	assert(domain);
	assert(len != 0);
	fwd_active = NULL;
	if (fwd_list == NULL)
		return 0;

	Forwarder *f = fwd_list;

	while (f) {
		if (len < f->name_len) {
			f = f->next;
			continue;
		}

		// exact match
		if (len == f->name_len) {
			if (strcmp(domain, f->name) == 0) {
				fwd_active = f;
				return 1;
			}
		}

		// check the ending of the domain name and affix a '.'
		int delta = len - f->name_len;
		if (strcmp(domain + delta, f->name) == 0) {
			if (*(domain + delta - 1) == '.') {
				fwd_active = f;
				return 1;
			}
		}

		f = f->next;
#ifdef HAVE_GCOV
	__gcov_flush();
#endif
	}

	return 0;
}

