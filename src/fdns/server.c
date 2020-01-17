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
#include "timetrace.h"
#include <sys/wait.h>

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

// test the server pointed by arg_server
// this function shuold be run in a separate process
// exit(0) if ok, exit(1) if error
static void test_server(void)  {
	// disable logging
	log_disable();

	ssl_init();

	printf("Testing server %s\n", arg_server);
	fflush(0);

	timetrace_start();
	ssl_open();
	if (ssl_state == SSL_CLOSED) {
		fprintf(stderr, "\tError: cannot open SSL connection to server %s\n", arg_server);
		fflush(0);
		exit(1);
	}
	float ms = timetrace_end();
	printf("\tSSL connection opened in %.02f ms\n", ms);
	fflush(0);

	timetrace_start();
	ssl_keepalive();
	ssl_keepalive();
	ssl_keepalive();
	ssl_keepalive();
	ssl_keepalive();
	ms = timetrace_end();
	if (ssl_state == SSL_CLOSED) {
		fprintf(stderr, "\tError: SSL connection closed\n");
		fflush(0);
		exit(1);
	}
	printf("\tDoH response average %.02f ms\n", ms / 5);
	fflush(0);

	exit(0);
}

//**************************************************************************
// public interface
//**************************************************************************
void server_list(void) {
	load_list();
	DnsServer *s = slist;

	while (s) {
		printf("%s - %s\n", s->name, s->tags);
		printf("\t%s\n", s->website);

		s = s->next;
	}
}

DnsServer *server_get(void) {
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
			return scurrent;
		}
		s = s->next;
	}

	// look for a tag
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

	if (!cnt) {
		fprintf(stderr, "Error: no server %s found in %s\n", arg_server, PATH_ETC_SERVER_LIST);
		exit(1);
	}

	// pick a random server
	int index = rand() % cnt + 1;
	if (arg_debug)
		printf("tag index %d\n", index);
	s = slist;
	while (s) {
		if (s->active == index) {
			if (server_test(s->name)) {
				// mark the server as inactive and try again
				s->active = 0;
				s = slist;
				// try several times to pick a different random server
				int newindex = rand() % cnt + 1;
				if (index == newindex)
					newindex = rand() % cnt + 1;
				if (index == newindex)
					newindex = rand() % cnt + 1;
				index = newindex;
				continue;
			}

			scurrent = s;
			free(arg_server);
			arg_server = strdup(s->name);
			if (!arg_server)
				errExit("strdup");
			return scurrent;
		}
		s = s->next;
	}

	fprintf(stderr, "Error: cannot connect to server %s\n", arg_server);
	exit(1);
}



// return 0 if ok, 1 if failed
int server_test(const char *server_name)  {
	// initialize server structure
	arg_server = strdup(server_name);
	if (!arg_server)
		errExit("strdup");

	pid_t child = fork();
	if (child == 0) { // child
		test_server();
		assert(0); // it will never get here
	}
	int status = 0;
	// wait for the child to finish
	int i = 0;
	do {
		int rv = waitpid(child, &status, WNOHANG);
		if (rv  == child) {
			// check status
			if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
				printf("\tError: server %s failed\n", arg_server);
				fflush(0);
				return 1;
			}
			break;
		}
		sleep(1);
		i++;
	}
	while (i < 5);
	if (i == 5) {
		printf("\tError: server %s failed\n", arg_server);
		fflush(0);
		kill(child, SIGKILL);
		return 1;
	}

	return 0;
}

void server_test_all(void)  {
	// load server list
	load_list();

	// walk the list
	DnsServer *s = slist;
	while (s) {
		scurrent = s;
		server_test(s->name);
		s = s->next;
	}

	printf("\nTesting completed\n");
}
