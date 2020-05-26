/*
 * Copyright (C) 2019-2020 FDNS Authors
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
#include <time.h>

int server_print_zone = 0;
int server_print_servers = 0;


static char *fdns_zone = NULL;
static DnsServer *slist = NULL;
static DnsServer *scurrent = NULL;
static char *push_request_tail =
	"Accept: application/dns-message\r\n" \
	"Content-Type: application/dns-message\r\n" \
	"Content-Length: %d\r\n" \
	"\r\n";

static inline void print_server(DnsServer *s) {
	assert(s);
	if (server_print_servers) {
		printf("%s - %s\n", s->name, s->tags);
		printf("\t%s\n", s->website);
	}
}

static void set_zone(void) {
	if (arg_zone) {
		// check valid zone
		if (strcmp(arg_zone, "Europe") != 0 &&
		    strcmp(arg_zone, "Asia-Pacific") != 0 &&
		    strcmp(arg_zone, "Americas-East") != 0 &&
		    strcmp(arg_zone, "Americas-West") != 0) {
		    	fprintf(stderr, "Error: invalid zone\n");
		    	exit(1);
		}

		fdns_zone = arg_zone;
		if (server_print_zone)
			printf("Current zone: %s\n", fdns_zone);
		return;
	}

	// get timezone
	tzset();
	int tz = -(timezone / 60) / 60;
	fdns_zone = "unknown";

	if (tz <= 14 && tz >= 4)
		fdns_zone = "Asia-Pacific";
	else if (tz <= 3 && tz >= -1)
		fdns_zone = "Europe";
	else if (tz <= -3 && tz >= -6)
		fdns_zone = "Americas-East";
	else if (tz <= -7 && tz >= -11)
		fdns_zone = "Americas-West";

	if (server_print_zone)
		printf("Current zone: %s\n", fdns_zone);
}

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
		else if (strncmp(buf, "zone: ", 6) == 0) {
			if (s->zone)
				goto errout;
			s->zone = strdup(buf + 6);
			if (!s->zone)
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

// todo: accept a server name in parallel with IP addresses
			// check address:port
			// commons.host is a geocast host
			// OpenSSL will find out the IP address using regular DNS over UDP
			if (strcmp(s->name, "commons.host") != 0) {
				if (check_addr_port(s->address)) {
					fprintf(stderr, "Error: file %s, line %d, invalid address:port\n", fname, *linecnt);
					exit(1);
				}
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
			if (!str) {
				free(s);
				fprintf(stderr, "Error: file %s, line %d, invalid host\n", fname, *linecnt);
				exit(1);
			}
			s->path = strdup(str);
			if (!s->path)
				errExit("strdup");
			*str++ = '\0';
		}
		else if (strncmp(buf, "sni: ", 5) == 0) {
			if (s->sni)
				goto errout;
			if (strcmp(buf + 5, "yes") == 0)
				s->sni = 1;
			else if (strcmp(buf + 5, "no") == 0)
				s->sni = 0;
			else {
				fprintf(stderr, "Error: file %s, line %d, wrong SNI setting\n", fname, *linecnt);
				exit(1);
			}
		}
		else if (strncmp(buf, "keepalive: ", 11) == 0) {
			if (s->keepalive)
				goto errout;
			if (sscanf(buf + 11, "%d", &s->keepalive) != 1 || s->keepalive <= 0) {
				fprintf(stderr, "Error: file %s, line %d, invalid keepalive\n", fname, *linecnt);
				exit(1);
			}
//			s->keepalive = 25;

			// check server data
			if (!s->name || !s->website || !s->zone || !s->tags || !s->address || !s->host) {
				fprintf(stderr, "Error: file %s, line %d, one of the server fields is missing\n", fname, *linecnt);
				exit(1);
			}

			// add host to filter
			if (!arg_allow_local_doh)
				filter_add('D', s->host);

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
}

static void load_list(void) {
	if (slist)
		return;
	if (fdns_zone == NULL)
		set_zone();

	// load all server entries from /etc/fdns/servers in list
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
// return 0 if ok, 1 if failed
int test_server(const char *server_name)  {
	if (arg_fallback_only)
		return 0;

	// initialize server structure
	arg_server = strdup(server_name);
	if (!arg_server)
		errExit("strdup");
	assert(scurrent);

	pid_t child = fork();
	if (child == 0) { // child
		assert(scurrent);

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
		h2_send_exampledotcom();
		h2_send_exampledotcom();
		h2_send_exampledotcom();
		h2_send_exampledotcom();
		h2_send_exampledotcom();
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
	while (i < 10); // 10 second wait

	if (i == 10) {
		printf("\tError: server %s failed\n", arg_server);
		fflush(0);
		kill(child, SIGKILL);
		return 1;
	}

	return 0;
}

//**************************************************************************
// public interface
//**************************************************************************
static int second_try = 0;
// mark all the servers corresponding to the given tag (s->active)
void server_list(const char *tag) {
	load_list();
	assert(slist);
	assert(fdns_zone);

	// if no tag provided use the current zone name
	if (!tag)
		tag = fdns_zone;

	// if the tag is the name of a zone use zone "any"
	if (strcmp(tag, "Europe") == 0 ||
	    strcmp(tag, "Asia-Pacific") == 0 ||
	    strcmp(tag, "Americas-East") == 0 ||
	    strcmp(tag, "Americas-West") == 0 ||
	    strcmp(tag, "Americas") == 0)
	    	fdns_zone = "any";

	// process tag "all"
	DnsServer *s = slist;
	int cnt = 0;
	if (strcmp(tag, "all") == 0) {
		while (s) {
			print_server(s);
			s->active = ++cnt;
			s = s->next;
		}
		if (server_print_servers)
			printf("%d servers found\n", cnt);
		return;
	}

	// try to match a server name
	s = slist;
	while (s) {
		if (strcmp(tag, s->name) == 0) {
			s->active = 1;
			print_server(s);
			return;
		}
		s = s->next;
	}

	// match tags/zones
	s = slist;
	cnt = 0;
	while (s) {
		// match the tag
		if (strstr(s->tags, tag) == NULL) {
			s = s->next;
			continue;
		}

		// match the zone if the zone is not "any"
		if (strcmp(fdns_zone, "any") && strstr(s->zone, fdns_zone) == NULL) {
			s = s->next;
			continue;
		}

		print_server(s);
		s->active = ++cnt;
		s = s->next;
	}

	if (cnt) {
		if (server_print_servers)
			printf("%d servers found\n", cnt);
	}
	else if (second_try == 0) {
		// try to find server outside the current zone
		second_try = 1;
		fdns_zone = "any";
		server_list(tag);
		return;
	}
	else
		printf("Sorry, no such server available.\n");
}

// get a pointer to the current server
// if arg_server was not set, use the current zone as a tag
DnsServer *server_get(void) {
	if (scurrent)
		return scurrent;

	load_list();
	if (!slist) {
		fprintf(stderr, "Error: the server list %s is empty", PATH_ETC_SERVER_LIST);
		exit(1);
	}


	// update arg_server
	if (arg_server == NULL) {
		assert(fdns_zone);
		arg_server = strdup(fdns_zone);
		if (!arg_server)
			errExit("strdup");
	} // arg_server is in mallocated memory
	if (arg_fallback_only) {
		scurrent = slist;
		return scurrent;
	}

	// initialize s->active
	server_list(arg_server);


	// count the servers
	int cnt = 0;
	assert(slist);
	DnsServer *s = slist;
	while (s) {
		if (s->active)
			cnt++;
		s = s->next;
	}
	if (cnt == 0)
		goto errout;

	// choose a random server
	int index = rand() % cnt + 1;
	if (arg_debug)
		printf("tag index %d\n", index);
	s = slist;
	while (s) {
		if (s->active == index) {
			scurrent = s;
			if (arg_id == -1 && test_server(s->name)) {
				// mark the server as inactive and try again
				s->active = 0;
				// set new active count
				s = slist;
				int cnt2 = 0;
				while (s) {
					if (s->active)
						s->active = ++cnt2;
					s = s->next;
				}
				s = slist;
				assert(cnt2 == (cnt - 1));
				cnt = cnt2;
				if (cnt == 0)
					goto errout;

				// try again
				index = rand() % cnt + 1;
				if (arg_debug)
					printf("new tag index %d\n", index);

				continue;
			}

			free(arg_server);
			arg_server = strdup(s->name);
			if (!arg_server)
				errExit("strdup");
			return scurrent;
		}
		s = s->next;
	}

errout:
	fprintf(stderr, "Error: cannot connect to server %s\n", arg_server);
	exit(1);
}




void server_test_tag(const char *tag)  {
	server_list(tag);
	// walk the list
	DnsServer *s = slist;
	while (s) {
		if (s->active) {
			scurrent = s;
			test_server(s->name);
		}
		s = s->next;
	}

	printf("\nTesting completed\n");
}
