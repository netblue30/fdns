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
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <openssl/opensslv.h>

int server_print_servers = 0;
int server_print_unlist = 1;

static char *fdns_zone = NULL;
static DnsServer *slist = NULL;
static DnsServer *scurrent = NULL;	// current DoH/DoT server


static inline void print_server(DnsServer *s) {
	assert(s);
	if (server_print_servers) {
		printf("%s - %s\n", s->name, s->tags);
		printf("\t%s\n", s->website);
	}
}

static void set_zone(void) {
	// get local timezone
	tzset();
	int tz = -(timezone / 60) / 60;
	fdns_zone = "unknown";

	if (tz <= 14 && tz >= 4)
		fdns_zone = "AsiaPacific";
	else if (tz <= 3 && tz >= -1)
		fdns_zone = "Europe";
	else if (tz <= -3 && tz >= -11)
		fdns_zone = "America";

	if (arg_id <= 0)
		printf("Current zone: %s\n", fdns_zone);
}

// split lines formatted as tok2: tok2
static char *tok1;
static char *tok2;
int split1(char *buf) {
	assert(buf);
	tok1 = NULL;
	tok2 = NULL;

	char *ptr = strchr(buf, ';');
	if (!ptr)
		return 1;
	*ptr = '\0';

	tok1 = buf;
	while (*tok1 == ' ' || *tok1 == '\t')
		tok1++;
	return 0;
}

int split2(char *buf) {
	assert(buf);
	tok1 = NULL;

	tok2 = strchr(buf, ':');
	if (!tok2)
		return 1;

	tok1 = buf;
	while (*tok1 == ' ' || *tok1 == '\t')
		tok1++;
	*tok2 = '\0';

	tok2++;
	while(*tok2 == ' ' || *tok2 == '\t')
		tok2++;
	if (*tok2 == '\0')
		return 1;

	char *ptr = tok2 + strlen(tok2) - 1;;
	while (*ptr == ' ' || *ptr == '\t')
		ptr--;
	*(ptr + 1) = '\0';

	return 0;
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

	// keepalive autodetection
	if (arg_keepalive)
		s->keepalive = arg_keepalive;
	else
		s->keepalive = DNS_KEEPALIVE_DEFAULT;

	char buf[4096];
	buf[0] = '\0';
	int host = 0;
	int quic = 0;
	while (fgets(buf, 4096, fp)) {
		(*linecnt)++;

		// comments
		if (*buf == '#')
			continue;

		// remove \n, split line in tok1 and tok2
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		if (strlen(buf) == 0)
			continue;
		if (split2(buf)) {
			if (split1(buf)) {
				fprintf(stderr, "Error: file %s, line %d, invalid command\n", fname, *linecnt);
				exit(1);
			}
		}
//printf("parser: #%s#, #%s#\n", tok1, (tok2)? tok2: "nil");

		if (!host) {
			if (tok2 == NULL) {
				fprintf(stderr, "Error: file %s, line %d, invalid command\n", fname, *linecnt);
				exit(1);
			}

			if (strcmp(tok1, "unlist") == 0) {
				unlisted_add(tok2);
				continue;
			}
		}

 		if (strcmp(tok1, "end") != 0 && tok2 == NULL) {
			fprintf(stderr, "Error: file %s, line %d, invalid command\n", fname, *linecnt);
			exit(1);
		}

		if (strcmp(tok1, "name") == 0) {
			if (s->name)
				goto errout;
			assert(tok2);
			s->name = strdup(tok2);
			if (!s->name)
				errExit("strdup");
			host = 1;
		}
		else if (strcmp(tok1, "website") == 0) {
			if (s->website)
				goto errout;
			assert(tok2);
			s->website = strdup(tok2);
			if (!s->website)
				errExit("strdup");
			host = 1;
		}
		else if (strcmp(tok1, "tags") == 0) {
			if (s->tags)
				goto errout;
			assert(tok2);
			s->tags = strdup(tok2);
			if (!s->tags)
				errExit("strdup");
			host = 1;

			if (strstr(s->tags, "dot,"))
				s->transport = "dot";
			if (strstr(s->tags, "quic,")) {
				s->transport = "quic";
				quic = 1;
			}
			if (strstr(s->tags, "sni,"))
				s->sni = 1;
			if (strstr(s->tags, "h2ping,"))
				s->h2ping = 1;
		}
		else if (strcmp(tok1, "address") == 0) {
			if (s->address)
				goto errout;
			assert(tok2);

			// check format: ip:port or domain:port
			char *ptr = strchr(tok2, ':');
			if (!ptr) {
				free(s);
				fprintf(stderr, "Error: file %s, line %d, invalid address\n", fname, *linecnt);
				exit(1);
			}
			s->address = malloc(strlen(tok2) + 3 + 1); // leave room  to switch port to 853 (dot)
			if (!s->address)
				errExit("malloc");
			strcpy(s->address, tok2);
			host = 1;
		}
		else if (strcmp(tok1, "host") == 0) {
			if (s->host)
				goto errout;
			assert(tok2);
			s->host = strdup(tok2);
			if (!s->host)
				errExit("strdup");
			host = 1;


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

		else if (strcmp(tok1, "keepalive") == 0) {
			assert(tok2);

			if (sscanf(tok2, "%d", &s->keepalive) != 1 || s->keepalive <= 0) {
				fprintf(stderr, "Error: file %s, line %d, invalid keepalive\n", fname, *linecnt);
				exit(1);
			}
		}

		else if (strcmp(tok1, "end") == 0) {
			assert(tok2 == NULL);
			// check server data

			if (!s->name || !s->website || !s->tags || !s->address || !s->host) {
				fprintf(stderr, "Error: file %s, line %d, one of the server fields is missing\n", fname, *linecnt);
				exit(1);
			}

			// check unlisted servers
			if (unlisted_find(s->name))
				return  read_one_server(fp, linecnt, fname);

			// check quic support
			if (quic && OPENSSL_VERSION_NUMBER < 0x30500000)
				return  read_one_server(fp, linecnt, fname);

			if (!s->transport)
				s->transport = "h2, http/1.1";

			return s;
		}
		else {
			fprintf(stderr, "Error: file %s, line %d, invalid command\n", fname, *linecnt);
			exit(1);
		}
	}
	tok1 = NULL;
	tok2 = NULL;

	if (host) {
		free(s);
		fprintf(stderr, "Error: file %s, line %d, keepalive missing\n", fname, *linecnt);
		exit(1);
	}

	free(s);
	return NULL;	// no  more servers in the configuration file

errout:
	free(s);
	tok1 = NULL;
	tok2 = NULL;
	fprintf(stderr, "Error: file %s, line %d, field defined twice\n", fname, *linecnt);
	exit(1);
}

static int load_file(const char *fname) {
	assert(fname);

	// load all server entries from fname in list
	FILE *fp = fopen(fname, "r");
	if (!fp)
		return 1;

	int linecnt = 0; // line counter
	DnsServer **ptr = &slist;

	// go to the end of the list
	while (*ptr != NULL) {
		ptr = &(*ptr)->next;
	}

	while (1) {
		DnsServer *s = read_one_server(fp, &linecnt, fname);
		if (!s)
			break;

		// push the server to the end of the list
		*ptr = s;
		ptr = &s->next;
	}

	fclose(fp);
	return 0;
}

static void load_list(void) {
	if (slist)
		return;
	if (fdns_zone == NULL)
		set_zone();

	assert(arg_server_list);
	if (load_file(arg_server_list)) {
		fprintf(stderr, "Error: cannot find server file %s\n", arg_server_list);
		exit(1);
	}
}


// return the average query time in ms, or 0 if failed
static float test_server(const char *server_name)  {
	// initialize server structure
	arg_server = strdup(server_name);
	if (!arg_server)
		errExit("strdup");
	assert(scurrent);

	int pipefd[2];
	if (pipe(pipefd) == -1)
		errExit("pipe");

	pid_t child = fork();
	if (child == 0) { // child
		assert(scurrent);
		close(pipefd[0]);

		// disable logging
		log_disable();
		ssl_init();
		printf("\nTesting server %s\n", arg_server);
		DnsServer *s = server_get();
		assert(s);
		if (s->tags)  // servers set from command line don't have a tag
			printf("   Tags: %s\n", s->tags);
		fflush(0);

		timetrace_start();
		if (strcmp(s->transport, "quic") == 0)
			 ssl_test_open();
		ssl_open();
		if (ssl_state == SSL_CLOSED) {
			fprintf(stderr, "   Error: cannot open SSL connection to server %s\n", arg_server);
			fflush(0);
			exit(0);
		}

		float ms = timetrace_end();
		printf("   SSL/TLS connection: %.02f ms\n", ms);
		fflush(0);

		// is not necessary to check the return data for example.com; this is already done during SSL connect
		timetrace_start();
		uint8_t buf[MAXBUF];
		transport->send_exampledotcom(buf);
		transport->send_exampledotcom(buf);
		transport->send_exampledotcom(buf);
		ms = timetrace_end();
		sleep(1);
		timetrace_start();
		transport->send_exampledotcom(buf);
		transport->send_exampledotcom(buf);
		transport->send_exampledotcom(buf);
		float ms2 = timetrace_end();

		if (ssl_state == SSL_CLOSED) {
			fprintf(stderr, "   Error: SSL connection closed\n");
			fflush(0);
			exit(1);
		}
		float average = (ms + ms2) / 6;
		int rv = write(pipefd[1], &average, sizeof(average));
		if (rv != sizeof(average)) {
			fflush(0);
			exit(1);
		}
		printf("   %s query average: %.02f ms\n", transport->dns_type, average);
		if (arg_details)
			transport->header_stats();
		double bdw = transport->bandwidth();
		if (bdw != 0)
			printf("   %s/Do53 bandwidth ratio: %0.02f\n", transport->dns_type, bdw);

		fflush(0);
		exit(0);
	}
	close(pipefd[1]);

	// wait for the child to finish
	int i = 0;
	float qaverage = 0; // query average time in ms
	do {
		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(pipefd[0], &readfds);
		struct timeval t = {1, 0};
		int rv = select(pipefd[0] + 1, &readfds, NULL, NULL, &t);
		if (rv == -1)
			goto ret;
		if (FD_ISSET(pipefd[0], &readfds)) {
			rv = read(pipefd[0], &qaverage, sizeof(qaverage));
			if (rv != sizeof(qaverage))
				goto ret;
			break;
		}


		int status = 0;
		rv = waitpid(child, &status, WNOHANG);
		if (rv  == child) {
			// check child status
			if (WIFEXITED(status) && WEXITSTATUS(status) == 1) {
				printf("   Error: server %s failed\n", arg_server);
				goto ret;
			}
			break;
		}
		i++;
	}
	while (i < 10); // 10 second wait

ret:
	fflush(0);
	kill(child, SIGKILL);
	int status;
	waitpid(child, &status, 0);

	return qaverage;
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
	if (tag == NULL)
		tag = fdns_zone;
//printf("### %s ### %s ###\n", tag, fdns_zone);

	// if the tag is the name of a zone, use it as our zone
	if (strcmp(tag, "Europe") == 0) {
		fdns_zone = "Europe";
		tag = NULL;
	}
	else if (strcmp(tag, "AsiaPacific") == 0) {
		fdns_zone = "AsiaPacific";
		tag = NULL;
	}
	else if (strcmp(tag, "America") == 0) {
		fdns_zone = "America";
		tag = NULL;
	}

	// extract family tag
	int family = 0;
	if (tag && strcmp(tag, "family") == 0) {
		family = 1;
		tag = NULL;
	}

//printf("here %d: %s # %s # %d\n", __LINE__, tag, fdns_zone, family);fflush(0);
	// process tag "all" - allow all zones and allow family tag
	DnsServer *s = slist;
	int cnt = 0;
	if (tag && strcmp(tag, "all") == 0) {
		while (s) {
			print_server(s);
			s->active = 1;
			cnt++;
			s = s->next;
		}

		if (server_print_servers)
			printf("%d server%s found\n", cnt, (cnt > 1)? "s": "");
		return;
	}


	// try to match a server name - allow family tag, allow any zone
	s = slist;
	while (s) {
		if (tag && strcmp(tag, s->name) == 0) {
			s->active = 1;
			print_server(s);
			return;
		}
		s = s->next;
	}

	// match tags: look for zone, family, and tag
	s = slist;
	cnt = 0;
	while (s) {
		// match family
//printf("********\n********%s # %s\n", s->name, s->tags);
		if (family && strstr(s->tags, "family") == NULL) {
			s = s->next;
			continue;
		}
		if (!family && strstr(s->tags, "family") != NULL) {
			s = s->next;
			continue;
		}

		// match zone if zone other than any
		if (strcmp(fdns_zone, "any") != 0 && strstr(s->tags, fdns_zone) == NULL) {
			s = s->next;
			continue;
		}

		// match tag
		if (tag) {
			if (strstr(s->tags, tag) == NULL) {
				s = s->next;
				continue;
			}
		}

		print_server(s);
		s->active = 1;
		cnt++;
		s = s->next;
	}


	if (cnt) {
		if (server_print_servers)
			printf("%d server%s found\n", cnt, (cnt > 1)? "s": "");
	}
	else if (second_try == 0) {
		// try to find server outside the current zone
		second_try = 1;
		fdns_zone = "any";
		server_list(tag);
		return;
	}
	else
		printf("Error: no such server available.\n");
}


static int count_active_servers(void) {
	static int printed = 0;
	int cnt = 0;
	assert(slist);
	DnsServer *s = slist;
	while (s) {
		if (s->active)
			cnt++;
		s = s->next;
	}

	if (arg_id < 0 && !printed)
		printf("%d server%s found\n", cnt, (cnt > 1)? "s": "");
	printed = 1;
	return cnt;
}


static DnsServer *random_server(void) {
	int cnt = count_active_servers();
	if (cnt == 0)
		return NULL;
	int index = rand() % cnt;
//printf("index %d\n", index);
	int i = 0;
	DnsServer *s = slist;
	while (s) {
		if (!s->active) {
			s = s->next;
			continue;
		}

		if (i == index)
			return s;
		i++;
		s = s->next;
	}
	assert(0);
	return NULL;
}

// get a pointer to the current server
// if arg_server was not set, use the current zone as a tag
DnsServer *server_get(void) {
	if (scurrent)
		return scurrent;

	load_list();
	if (!slist) {
		fprintf(stderr, "Error: the server list %s is empty\n", arg_server_list);
		exit(1);
	}

	// update arg_server
	if (arg_server == NULL) {
		assert(fdns_zone);
		arg_server = strdup(fdns_zone);
		if (!arg_server)
			errExit("strdup");
	} // arg_server is in mallocated memory

	// initialize s->active
	server_list(arg_server);

	// choose a random server
	int cnt = count_active_servers();
	DnsServer *s = random_server();
	if (s == NULL)
		goto errout;

	while (s) {
		scurrent = s;
		if (arg_id == -1) { // testing only in frontend process
			float qaverage = test_server(s->name);
			if (qaverage == 0) {
				s->active = 0;
				s = random_server();
				continue;
			}
			else if (cnt > 1) {
				// try another server
				DnsServer *first = s;
				float first_average = qaverage;
				scurrent = first;
				stats.query_time = first_average;
				if (first_average > QTIME_RANDOM_LIMIT) {
					// try another server
					s = random_server();
					if (s == first) // try again
						s = random_server();
					scurrent = s;
					qaverage = test_server(s->name);
					stats.query_time = qaverage;

					// grab the fastest one
					if (qaverage == 0 || qaverage > first_average) {
						// revert back to the first server
						scurrent = first;
						s = first;
						stats.query_time = first_average;
					}
				}
			}
		}
		// else - no testing in the resolver processes

		assert(arg_server);
		free(arg_server);
		arg_server = strdup(s->name);
		if (!arg_server)
			errExit("strdup");
		return scurrent;
	}


errout:
	fprintf(stderr, "Error: cannot connect to server %s\n", arg_server);
	return NULL;
}

void server_test_tag(const char *tag)  {
	server_list(tag);

	// walk the list
	DnsServer *s = slist;
	int cnt = 0;
	while (s) {
		if (s->active) {
			scurrent = s;
			float rv = test_server(s->name);
			if (rv != 0) {
				stats_add(s->name, rv);
				cnt++;
			}
			else
				stats_down(s->name);
			usleep(500000);
		}
		s = s->next;
	}

	printf("\n");
	if (cnt == 0)
		printf("No active servers found\n");
	else
		stats_print();
	printf("Testing completed\n");
}

void server_set_custom(const char *url) {
	set_zone();
	slist = malloc(sizeof(DnsServer));
	if (!slist)
		errExit("malloc");
	memset(slist, 0, sizeof(DnsServer));

	DnsServer *s = slist;
	int dot_transport = 0;
	if (strncmp(url, "https://", 8) == 0) {
		s->host = strdup(url + 8); // skip https://
		s->transport = "h2, http/1.1";
	}
	else if (strncmp(url, "dot://", 6)  == 0) {
		s->host = strdup(url + 6); // skip dot://
		s->tags = "dot";
		s->transport = "dot";
		dot_transport = 1;
	}
	else if (strncmp(url, "quic://", 7)  == 0) {
		s->host = strdup(url + 7); // skip quic://
		s->tags = "quic";
		s->transport = "quic";
		dot_transport = 1;
	}
	else
		assert(0);
	if (!s->host)
		errExit("strdup");

	// build the DNS/HTTP request
	char *str = strchr(s->host, '/');
	if (!str)
		s->path = "/";
	else {
		s->path = strdup(str);
		if (!s->path)
			errExit("strdup");
		*str++ = '\0';
	}

	if (strchr(s->host, ':') == NULL) {
		if (dot_transport) {
			if (asprintf(&s->address, "%s:853", s->host) == -1)
				errExit("asprintf");
		}
		else {
			if (asprintf(&s->address, "%s:443", s->host) == -1)
				errExit("asprintf");
		}
	}
	else {
		s->address = strdup(s->host);
		if (!s->address)
			errExit("strdup");
	}

	s->name = strdup(url);
	if (!s->name)
		errExit("strdup");
	s->website = "unknown";
	s->test_sni = 1;
	if (arg_keepalive)
		s->keepalive = arg_keepalive;
	else
		s->keepalive = DNS_KEEPALIVE_DEFAULT;

	scurrent = s;
}

