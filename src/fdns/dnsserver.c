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

static char *push_request_tail =
	"accept: application/dns-message\r\n" \
	"content-type: application/dns-message\r\n" \
	"content-length: %d\r\n" \
	"\r\n";
static char *default_server_name = "cloudflare";
static char *active_server_name = NULL;
static DnsServer *default_server = NULL;
static DnsServer *active_server = NULL;
static char *requested_server = NULL;


// returns 0 if successful, -1 if error
static int read_one_server(FILE *fp, DnsServer *s, int *linecnt) {
	assert(fp);
	assert(s);
	assert(linecnt);
	memset(s, 0, sizeof(DnsServer));
	int found = 0;

	char buf[4096];
	buf[0] = '\0';
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
		else if (strncmp(buf, "description: ", 13) == 0) {
			if (s->description)
				goto errout;
			s->description = strdup(buf + 9);
			if (!s->description)
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
				fprintf(stderr, "Error: line %d, invalid address:port\n", *linecnt);
				return -1;
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
				fprintf(stderr, "Error: line %d, invalid keepalive\n", *linecnt);
				return -1;
			}

			// check server data
			if (!s->name || !s->website || !s->description || !s->address || !s->request1 || !s->request2) {
				fprintf(stderr, "Error: line %d, one of the server fields is missing\n", *linecnt);
				return -1;
			}

			// build the request
			if (asprintf(&s->request, "%s\r\n%s\r\n%s", s->request1, s->request2, push_request_tail) == -1)
				errExit("asprintf");
			return 0;
		}
	}

	if (found) {
		fprintf(stderr, "Error: line %d, keepalive missing\n", *linecnt);
		return -1;
	}
	return 0;	// the last server was already read

errout:
	fprintf(stderr, "Error: line %d, field defined twice\n", *linecnt);
	return -1;
}

void dns_list(void) {
	// print all server entries from /etc/fdns/servers
	FILE *fp = fopen(PATH_ETC_SERVER_LIST, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot find %s file. fdns is not correctly installed\n", PATH_ETC_SERVER_LIST);
		exit(1);
	}

	int linecnt = 0; // line counter
	while (1) {
		DnsServer s;
		int rv = read_one_server(fp, &s, &linecnt);
		if (rv == -1) {
			fprintf(stderr, "Error: invalid %s file\n", PATH_ETC_SERVER_LIST);
			exit(1);
		}

		// check if we are at the end of the file
		if (!s.name)
			break;

		// print name - website
		printf("%s - %s\n", s.name, s.website);

		// print description.
		printf("\t%s; SSL keepalive %ds\n", s.description, s.ssl_keepalive);
	}

	fclose(fp);
}

DnsServer *dns_set_server(const char *srv) {
	assert(srv);
	active_server_name = strdup(srv);
	if (active_server_name == NULL)
		errExit("strdup");

	// read server configuration
	return dns_get_server();
}

DnsServer *dns_get_server(void) {
	if (arg_debug)
		printf("dns_get_server pid %d, active_server %p\n", getpid(), active_server);

	if (active_server == NULL) {
		// initialize server
		active_server = malloc(sizeof(DnsServer));
		if (active_server == NULL)
			errExit("malloc");
		default_server = malloc(sizeof(DnsServer));
		if (default_server == NULL)
			errExit("malloc");

		// parse the server entries from /etc/fdns/servers
		FILE *fp = fopen(PATH_ETC_SERVER_LIST, "r");
		if (!fp) {
			fprintf(stderr, "Error: cannot find %s file. fdns is not correctly installed\n", PATH_ETC_SERVER_LIST);
			exit(1);
		}

		if (active_server_name == NULL)
			active_server_name = default_server_name;
		int linecnt = 0; // line counter
		while (1) {
			DnsServer s;
			int rv = read_one_server(fp, &s, &linecnt);
			if (rv == -1) {
				fprintf(stderr, "Error: invalid %s file\n", PATH_ETC_SERVER_LIST);
				exit(1);
			}
			// check if we went trough the file and didn't find the server
			if (s.name == NULL) {
				// if we extracted the default server, use it
				if (default_server->name == NULL) {
					fprintf(stderr, "Error: requested server not found, default server not found\n");
					exit(1);
				}
				memcpy(active_server, default_server, sizeof(DnsServer));
				logprintf("Warning: requested server not found, using %s\n", active_server->name);
				break;
			}

			// check requested server
			if (strcmp(s.name, active_server_name) == 0) {
				memcpy(active_server, &s, sizeof(DnsServer));
				break;
			}

			// check default server
			if (strcmp(s.name, default_server_name) == 0)
				memcpy(default_server, &s, sizeof(DnsServer));

		}
		fclose(fp);

		if (active_server->name == NULL) {
			fprintf(stderr, "Error: cannot set cloudflare as default server\n");
			exit(1);
		}
		if (arg_debug)
			printf("\tServer %s initialized %p\n", active_server->name, active_server);
	}

	if (arg_debug)
		printf("\tpid %d, server #%s#\n", getpid(), active_server->name);
	return active_server;
}

// build a list of servers from /etc/fdns/servers file and pick a random one
typedef struct slist_t {
	char *name;
	struct slist_t *next;
} SList;
static SList *server_list = NULL;
static int server_cnt = 0;

char *dns_get_random_server(void) {
	// parse the server entries from /etc/fdns/servers
	FILE *fp = fopen(PATH_ETC_SERVER_LIST, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot find %s file. fdns is not correctly installed\n", PATH_ETC_SERVER_LIST);
		exit(1);
	}

	int linecnt = 0; // line counter
	while (1) {
		DnsServer s;
		int rv = read_one_server(fp, &s, &linecnt);
		if (rv == -1) {
			fprintf(stderr, "Error: invalid %s file\n", PATH_ETC_SERVER_LIST);
			exit(1);
		}

		// empty list?
		if (!s.name)
			break;

		// don't use family services
		assert(s.description);
		if (strstr(s.description, "family filter"))
			continue;

		server_cnt++;
		SList *ptr = malloc(sizeof(SList));
		if (!ptr)
			errExit("malloc");
		ptr->name = strdup(s.name);
		if (!ptr->name)
			errExit("strdup");
		ptr->next = server_list;
		server_list = ptr;
	}
	fclose(fp);

	if (!server_cnt) {
		fprintf(stderr, "Error: the server list in %s is empty\n", PATH_ETC_SERVER_LIST);
		exit(1);
	}

	// init random number generator and pick a server
	srand(time(NULL));
	int index = rand() % server_cnt;
	int i;
	SList *ptr = server_list;
	for (i = 0; i < index; i++, ptr = ptr->next) ;

	assert(ptr->name);
	char *rv = strdup(ptr->name);
	if (!rv)
		exit(1);
	return rv;
}


