/*
 * Copyright (C) 2014-2019 fdns Authors
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
#include <time.h>

static DnsServer *slist = NULL;
static DnsServer *scurrent = NULL;
static char *push_request_tail =
	"accept: application/dns-message\r\n" \
	"content-type: application/dns-message\r\n" \
	"content-length: %d\r\n" \
	"\r\n";

// returns NULL for end of list
static DnsServer *read_one_server(FILE *fp, int *linecnt, const char *fname) {
	assert(fp);
	assert(linecnt);
	assert(fname);

	DnsServer *s = malloc(sizeof(DnsServer));
	if (!s)
		errExit("malloc");
	memset(s, 0, sizeof(DnsServer));

	char buf[4096];
	buf[0] = '\0';
	int found = 0;
	while (fgets(buf, 4096, fp)) {
		(*linecnt)++;

		// comments
		if (*buf == '#')
			continue;

		// remove \n
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';

		if (strncmp(buf, "name: ", 6) == 0) {
			if (s->name)
				goto errout;
			s->name = strdup(buf + 6);
			if (!s->name)
				errExit("strdup");
			found = 1;
		}
		else if (strncmp(buf, "website: ", 9) == 0) {
			if (s->website)
				goto errout;
			s->website = strdup(buf + 9);
			if (!s->website)
				errExit("strdup");
			found = 1;
		}
		else if (strncmp(buf, "tags: ", 6) == 0) {
			if (s->tags)
				goto errout;
			s->tags = strdup(buf + 6);
			if (!s->tags)
				errExit("strdup");
			found = 1;
		}
		else if (strncmp(buf, "address: ", 9) == 0) {
			if (s->address)
				goto errout;
			s->address = strdup(buf + 9);
			if (!s->address)
				errExit("strdup");

			// check address:port
			if (check_addr_port(s->address)) {
				fprintf(stderr, "Error: file %s, line %d, invalid address:port\n", fname, *linecnt);
				errExit("read server file");
			}
			found = 1;
		}
		else if (strncmp(buf, "request1: ", 10) == 0) {
			if (s->request1)
				goto errout;
			s->request1 = strdup(buf + 10);
			if (!s->request1)
				errExit("strdup");

			found = 1;
		}
		else if (strncmp(buf, "request2: ", 9) == 0) {
			if (s->request2)
				goto errout;
			s->request2 = strdup(buf + 10);
			if (!s->request2)
				errExit("strdup");

			found = 1;
		}
		else if (strncmp(buf, "keepalive: ", 11) == 0) {
			if (s->ssl_keepalive)
				goto errout;
			if (sscanf(buf + 11, "%d", &s->ssl_keepalive) != 1 || s->ssl_keepalive <= 0) {
				fprintf(stderr, "Error: file %s, line %d, invalid keepalive\n", fname, *linecnt);
				errExit("read server file");
			}

			// check server data
			if (!s->name || !s->website || !s->tags || !s->address || !s->request1 || !s->request2) {
				fprintf(stderr, "Error: file %s, line %d, one of the server fields is missing\n", fname, *linecnt);
				errExit("read server file");
			}

			// build the DNS/HTTP request
			if (asprintf(&s->request, "%s\r\n%s\r\n%s", s->request1, s->request2, push_request_tail) == -1)
				errExit("asprintf");
			return s;
		}
	}

	if (found) {
		free(s);
		fprintf(stderr, "Error: file %s, line %d, keepalive missing\n", fname, *linecnt);
		errExit("read server file");
	}
	free(s);
	return NULL;	// no  more servers in the configuration file

errout:
	free(s);
	fprintf(stderr, "Error: file %s, line %d, field defined twice\n", fname, *linecnt);
	errExit("read server file");
}


static void load_list(void) {
	assert(slist == NULL);

	// load all server entries from /etc/fdns/servers in slist
	FILE *fp = fopen(PATH_ETC_SERVER_LIST, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot find %s file. fdns is not correctly installed\n", PATH_ETC_SERVER_LIST);
		exit(1);
	}

	int linecnt = 0; // line counter
	DnsServer **ptr = &slist;
	while (1) {
		DnsServer *s = read_one_server(fp, &linecnt, PATH_ETC_SERVER_LIST);
		if (!s)
			break;
		// push it to the end of the list
		*ptr = s;
		ptr = &s->next;
	}

	fclose(fp);
}

//**************************************************************************
// public interface
//**************************************************************************
void dnsserver_list(void) {
	load_list();
	DnsServer *s = slist;

	while (s) {
		// print name - website
		printf("%s - %s\n", s->name, s->website);
		// print tags
		printf("\t%s\n", s->tags);

		s = s->next;
	}
}

DnsServer *dnsserver_get(void) {
	if (scurrent)
		return scurrent;
	if (!slist)
		load_list();
	if (!slist) {
		fprintf(stderr, "Error: the server list %s is empty", PATH_ETC_SERVER_LIST);
		exit(1);
	}

	// update arg_server
	if (arg_server == NULL) {
		arg_server = strdup("cloudflare");
		if (!arg_server)
			errExit("strdup");
	} // arg_server is in mallocated memory

	// find the server in the list and initialize the server structure
	DnsServer *s = slist;
	while (s) {
		if (strcmp(s->name, arg_server) == 0) {
			scurrent = s;
			break;
		}
		s = s->next;
	}

	// look for a tag
	if (!scurrent) {
		// mark the servers using arg_server as a tag
		s = slist;
		int cnt = 0;
		while (s) {
			assert(s->active == 0);
			if (strstr(s->tags, arg_server)) {
				if (arg_debug)
					printf("tag %s\n", s->name);
				cnt++;
				s->active = cnt;
			}
			s = s->next;
		}

		if (!cnt)
			goto errexit;

		// pick a random server
		srand(time(NULL));
		int index = rand() % cnt;
		index++;
		if (arg_debug)
			printf("tag index %d\n", index);

		s = slist;
		while (s) {
			if (s->active == index) {
				scurrent = s;
				free(arg_server);
				arg_server = strdup(s->name);
				if (!arg_server)
					errExit("strdup");
				break;
			}
			s = s->next;
		}
	}

	// end the program if the server is not found in the list
	if (!scurrent)
		goto errexit;

	return scurrent;

errexit:
	fprintf(stderr, "Error: cannot find server %s in %s\n", arg_server, PATH_ETC_SERVER_LIST);
	exit(1);

}

