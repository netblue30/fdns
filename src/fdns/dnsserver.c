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
#include "timetrace.h"
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
				exit(1);
			}
			found = 1;
		}
		else if (strncmp(buf, "host: ", 6) == 0) {
			if (s->host)
				goto errout;
			s->host = strdup(buf + 6);
			if (!s->host)
				errExit("strdup");
			found = 1;

			// build the DNS/HTTP request
			char *str = strchr(s->host, '/');
			if (!str)
				goto errout2;
			*str++ = '\0';
			if (asprintf(&s->request, "POST /%s HTTP/1.1\r\nHost: %s\r\n%s", str, s->host, push_request_tail) == -1)
				errExit("asprintf");
			if (arg_debug)
				printf("%s\n", s->request);
		}
		else if (strncmp(buf, "keepalive: ", 11) == 0) {
			if (s->ssl_keepalive)
				goto errout;
			if (sscanf(buf + 11, "%d", &s->ssl_keepalive) != 1 || s->ssl_keepalive <= 0) {
				fprintf(stderr, "Error: file %s, line %d, invalid keepalive\n", fname, *linecnt);
				exit(1);
			}

			// check server data
			if (!s->name || !s->website || !s->tags || !s->address || !s->host || !s->request) {
				fprintf(stderr, "Error: file %s, line %d, one of the server fields is missing\n", fname, *linecnt);
				exit(1);
			}

			return s;
		}
	}

	if (found) {
		free(s);
		fprintf(stderr, "Error: file %s, line %d, keepalive missing\n", fname, *linecnt);
		exit(1);
	}
	free(s);
	return NULL;	// no  more servers in the configuration file

errout:
	free(s);
	fprintf(stderr, "Error: file %s, line %d, field defined twice\n", fname, *linecnt);
	exit(1);

errout2:
	free(s);
	fprintf(stderr, "Error: file %s, line %d, invalid host\n", fname, *linecnt);
	exit(1);
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
		printf("%s - %s\n", s->name, s->tags);
		printf("\t%s\n", s->website);

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
		arg_server = strdup(DEFAULT_SERVER);
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

// return 0 if ok, 1 if failed
int dnsserver_test(const char *server_name)  {
	// disable logging
	log_disable();

	// initialize server structure
	arg_server = strdup(server_name);
	if (!arg_server)
		errExit("strdup");
	DnsServer *s = dnsserver_get();
	ssl_init();

	printf("Testing server %s\n", arg_server);

	timetrace_start();
	ssl_open();
	if (ssl_state == SSL_CLOSED) {
		fprintf(stderr, "Error: cannot open SSL connection\n");
		return 1;
	}
	float ms = timetrace_end();
	printf("SSL connection opened in %.02f ms\n", ms);

	timetrace_start();
	ssl_keepalive();
	ssl_keepalive();
	ssl_keepalive();
	ssl_keepalive();
	ssl_keepalive();
	ms = timetrace_end();
	if (ssl_state == SSL_CLOSED) {
		fprintf(stderr, "Error: SSL connection closed\n");
		return 1;
	}
	printf("DoH response average %.02f ms\n", ms/5);

	return 0;
}

void dnsserver_test_all(void)  {
	// disable logging
	log_disable();

	// load server list
	load_list();

	// walk the list
	DnsServer *s = slist;
	while (s) {
		scurrent = s;
		printf("%-20s - ", s->name);
		timetrace_start();
		ssl_open();
		if (ssl_state == SSL_CLOSED) {
			printf("open SSL failed\n");
			continue;
		}
		float ms = timetrace_end();
		printf("SSL open %.02f ms, ", ms);

		timetrace_start();
		ssl_keepalive();
		ssl_keepalive();
		ssl_keepalive();
		ssl_keepalive();
		ssl_keepalive();
		ms = timetrace_end();
		if (ssl_state == SSL_CLOSED) {
			printf("DoH request failed\n");
			continue;
		}
		printf("DoH average %.02f ms\n", ms/5);
		ssl_close();
		s = s->next;
	}
}
