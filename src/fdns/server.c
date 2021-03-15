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

int server_print_zone = 0;
int server_print_servers = 0;
int server_print_unlist = 1;


static int admin_down = 0; // set to 1 if --test-server=admin-down -> testing only servers disabled by admin-down flag
static char *fdns_zone = NULL;
static DnsServer *slist = NULL;
static DnsServer *scurrent = NULL;	// curernt DoH/DoT server
static DnsServer *fcurrent = NULL;	// current fallback server


static DnsServer fallback[] = {
	{ .name = "adguard", .address = "94.140.14.14"},	// adblock
	{ .name = "cleanbrowsing", .address = "185.228.168.9"},	// security
	{ .name = "cloudflare", .address = "1.1.1.2"},		// security
	{ .name = "nextdns", .address = "45.90.28.141" },	// security
	{ .name = "quad9", .address = "9.9.9.9"}		// security
};



typedef struct unlisted_t {
	struct unlisted_t *next;
	char *name;
} UnlistedElem;

UnlistedElem *unlisted = NULL;

static UnlistedElem *unlisted_find(const char *name) {
	assert(name);
	UnlistedElem *ptr = unlisted;

	while (ptr) {
		if (strcmp(name, ptr->name) == 0)
			return ptr;
		ptr = ptr->next;
	}

	return NULL;
}

static void unlisted_add(const char *name) {
	assert(name);
	if (server_print_unlist)
		printf("Unlisting %s\n", name);

	UnlistedElem *ptr = malloc(sizeof(UnlistedElem));
	if (!ptr)
		errExit("malloc");
	memset(ptr, 0, sizeof(UnlistedElem));
	ptr->name = strdup(name);
	if (!ptr->name)
		errExit("strdup");

	if (unlisted == NULL)
		unlisted = ptr;
	else {
		ptr->next = unlisted;
		unlisted = ptr;
	}
}

static inline void print_server(DnsServer *s) {
	assert(s);
	if (server_print_servers) {
		printf("%s - %s (keepalive %d)\n", s->name, s->tags, s->keepalive_max);
		printf("\t%s\n", s->website);
	}
}

static void set_zone(void) {
	if (arg_zone) {
		// check valid zone
		if (strcmp(arg_zone, "Europe") != 0 &&
		    strcmp(arg_zone, "AsiaPacific") != 0 &&
		    strcmp(arg_zone, "Americas") != 0) {
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
		fdns_zone = "AsiaPacific";
	else if (tz <= 3 && tz >= -1)
		fdns_zone = "Europe";
	else if (tz <= -3 && tz >= -11)
		fdns_zone = "Americas";

	if (server_print_zone)
		printf("Current zone: %s\n", fdns_zone);
}

// split lines formated as tok2: tok2
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

	char buf[4096];
	buf[0] = '\0';
	int host = 0;
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
			if (strcmp(tok1, "unlist") == 0) {
				unlisted_add(tok2);
				continue;
			}
			else if (strcmp(tok1, "block-doh") == 0) {
				if (arg_disable_local_doh)
					filter_serach_add('D', tok2);
				continue;
			}
		}

		if (strcmp(tok1, "name") == 0) {
			if (s->name)
				goto errout;
			s->name = strdup(tok2);
			if (!s->name)
				errExit("strdup");
			host = 1;
		}
		else if (strcmp(tok1, "website") == 0) {
			if (s->website)
				goto errout;
			s->website = strdup(tok2);
			if (!s->website)
				errExit("strdup");
			host = 1;
		}
		else if (strcmp(tok1, "zone") == 0) {
			if (s->zone)
				goto errout;
			s->zone = strdup(tok2);
			if (!s->zone)
				errExit("strdup");
			host = 1;
		}
		else if (strcmp(tok1, "tags") == 0) {
			if (s->tags)
				goto errout;
			s->tags = strdup(tok2);
			if (!s->tags)
				errExit("strdup");
			host = 1;
		}
		else if (strcmp(tok1, "address") == 0) {
			if (s->address)
				goto errout;
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
			if (arg_transport && strcmp(arg_transport, "dot") == 0) {
				ptr =strstr(s->address, ":");
				sprintf(ptr, "%s", ":853");
			}
			host = 1;
		}
		else if (strcmp(tok1, "host") == 0) {
			if (s->host)
				goto errout;
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
		else if (strcmp(tok1, "sni") == 0) {
			if (s->sni)
				goto errout;
			if (strcmp(tok2, "yes") == 0)
				s->sni = 1;
			else if (strcmp(tok2, "no") == 0)
				s->sni = 0;
			else {
				fprintf(stderr, "Error: file %s, line %d, wrong SNI setting\n", fname, *linecnt);
				exit(1);
			}
		}
		else if (strcmp(tok1, "transport") == 0) {
			if (s->transport)
				goto errout;
			s->transport = strdup(buf + 11);
			if (!s->transport)
				errExit("strdup");
			// todo: parser transport line
		}
		else if (strcmp(tok1, "keepalive-query") == 0) {
			if (s->keepalive_query)
				goto errout;
			if (strcmp(tok2, "yes") == 0)
				s->keepalive_query = 1;
			else if (strcmp(tok2, "no") == 0)
				s->keepalive_query = 0;
			else {
				fprintf(stderr, "Error: file %s, line %d, wrong keepalive-query setting\n", fname, *linecnt);
				exit(1);
			}
		}
		else if (strcmp(tok1, "keepalive") == 0) {
			if (s->keepalive_min)
				goto errout;

			// detect keepalive range
			if (strchr(tok2, ',')) {
				if (sscanf(tok2, "%d,%d", &s->keepalive_min, &s->keepalive_max) != 2 ||
				                s->keepalive_min <= 0 ||
				                s->keepalive_max <= 0 ||
				                s->keepalive_min > s->keepalive_max) {
					fprintf(stderr, "Error: file %s, line %d, invalid keepalive\n", fname, *linecnt);
					exit(1);
				}
			}
			else {
				if (sscanf(tok2, "%d", &s->keepalive_min) != 1 || s->keepalive_min <= 0) {
					fprintf(stderr, "Error: file %s, line %d, invalid keepalive\n", fname, *linecnt);
					exit(1);
				}
				s->keepalive_max = s->keepalive_min;
			}
			if (arg_keepalive) {
				s->keepalive_min = arg_keepalive;
				s->keepalive_max = arg_keepalive;
			}
		}
		else if (strcmp(tok1, "end") == 0) {
			// check server data
			if (!s->name || !s->website || !s->zone || !s->tags || !s->address || !s->host) {
				fprintf(stderr, "Error: file %s, line %d, one of the server fields is missing\n", fname, *linecnt);
				exit(1);
			}

			// check unlisted servers
			if (unlisted_find(s->name))
				return  read_one_server(fp, linecnt, fname);

			if (!s->transport)
				s->transport = "h2, http/1.1";

			// add host to filter
			if (arg_disable_local_doh)
				filter_serach_add('D', s->host);

			// servers tagged as admin-down are not taken into calculation
			if (admin_down == 0 && strstr(s->tags, "admin-down")) {
				free(s);
				// go to next server in the list
				return read_one_server(fp, linecnt, fname);
			}
			// only admin-down servers
			else if (admin_down == 1 && strstr(s->tags, "admin-down") == NULL) {
				free(s);
				// go to next server in the list
				return read_one_server(fp, linecnt, fname);
			}

			return s;
		}
		else {
			fprintf(stderr, "Error: file %s, line %d, invalid command\n", fname, *linecnt);
			exit(1);
		}
	}

	if (host) {
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

static int load_file(const char *fname) {
	assert(fname);

	// load all server entries from /etc/fdns/servers in list
	FILE *fp = fopen(fname, "r");
	if (!fp)
		return 1;

	int linecnt = 0; // line counter
	DnsServer **ptr = &slist;
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

	// process unlisted servers
	if (arg_unlist) {
		char *tmp = strdup(arg_unlist);
		if (!tmp)
			errExit("strdup");
		char *token = strtok(tmp, ",");
		while (token) {
			unlisted_add(token);
			token = strtok(NULL, ",");
		}
	}

	load_file(PATH_ETC_SERVER_LOCAL_LIST);
	if (load_file(PATH_ETC_SERVER_LIST)) {
		fprintf(stderr, "Error: cannot find %s file. fdns is not correctly installed\n", PATH_ETC_SERVER_LIST);
		exit(1);
	}
}


// return the average query time in ms, or 0 if failed
static uint8_t test_server(const char *server_name)  {
	if (arg_fallback_only)
		return 0;

	// initialize server structure
	arg_server = strdup(server_name);
	if (!arg_server)
		errExit("strdup");
	assert(scurrent);

	pid_t child = fork();
	if (child == 0) { // child
// exit 0 - error
// exit 1 - 255 - average query in ms
		assert(scurrent);

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
		ssl_open();
		if (ssl_state == SSL_CLOSED) {
			fprintf(stderr, "   Error: cannot open SSL connection to server %s\n", arg_server);
			fflush(0);
			exit(0);
		}

		float ms = timetrace_end();
		printf("   SSL/TLS connection: %.02f ms\n", ms);
		fflush(0);

		// is not necessary to check the return data for example.com; this is already done durring SSL connect
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
			exit(0);
		}
		float average = (ms + ms2) / 6;
		printf("   %s query average: %.02f ms\n", transport->dns_type, average);
		if (arg_details)
			transport->header_stats();
		printf("   %s/Do53 bandwidth ratio: %0.02f\n", transport->dns_type, transport->bandwidth());
		if (s->tags) { // servers set from command line don't have a tag
			if (s->keepalive_min == s->keepalive_max)
				printf("   Keepalive: %d seconds\n", s->keepalive_min);
			else
				printf("   Keepalive: %d to %d seconds\n", s->keepalive_min, s->keepalive_max);
		}

		fflush(0);
		uint8_t qaverage = (average > 255)? 255: average;
		if (qaverage == 0)
			qaverage = 1;
		exit(qaverage);
	}

	// wait for the child to finish
	int i = 0;
	uint8_t qaverage = 0; // query average time in ms
	do {
		int status = 0;
		int rv = waitpid(child, &status, WNOHANG);
		if (rv  == child) {
			qaverage = WEXITSTATUS(status);
			// check child status
			if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
				printf("   Error: server %s failed\n", arg_server);
				fflush(0);
				return 0;
			}
			break;
		}
		sleep(1);
		i++;
	}
	while (i < 20); // 20 second wait

	if (i == 20) {
		printf("   Error: server %s failed\n", arg_server);
		fflush(0);
		kill(child, SIGKILL);
		return 0;
	}

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

	// if no tag provided use the current zone name
	if (!tag)
		tag = fdns_zone;

	// if the tag is the name of a zone use zone "any"
	if (strcmp(tag, "Europe") == 0 ||
	    strcmp(tag, "AsiaPacific") == 0 ||
	    strcmp(tag, "Americas") == 0)
	    	fdns_zone = "any";

	// process tag "all"
	DnsServer *s = slist;
	int cnt = 0;
	if (strcmp(tag, "all") == 0 || strcmp(tag, "admin-down") == 0) {
		while (s) {
			// match transport
			if (arg_transport) {
				if (strstr(s->transport, arg_transport) == NULL) {
					s = s->next;
					continue;
				}
			}
			print_server(s);
			s->active = 1;
			cnt++;
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
			if (!arg_transport && s->transport && strstr(s->transport, "dot"))
				arg_transport = "dot";
			return;
		}
		s = s->next;
	}

	// match tags/zones
	s = slist;
	cnt = 0;
	while (s) {
		// match tag
		char *ptr = strstr(s->tags, tag);
		if (ptr == NULL) {
			// try to match Americas
			if (strcmp(tag, "Americas") == 0 && strstr(s->tags, "America"))
				;
			else {
				s = s->next;
				continue;
			}
		}

		// match end of tag
		if (ptr) {
			ptr += strlen(tag);
			if (*ptr != '\0' && *ptr != ',') { // we are somewhere in the middle of a tag
				s = s->next;
				continue;
			}
		}

		// match the zone if the zone is not "any"
		if (strcmp(fdns_zone, "any") && strstr(s->zone, fdns_zone) == NULL) {
			s = s->next;
			continue;
		}

		// match transport
		if (arg_transport) {
			if (strstr(s->transport, arg_transport) == NULL) {
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


static int count_active_servers(void) {
	int cnt = 0;
	assert(slist);
	DnsServer *s = slist;
	while (s) {
		if (s->active)
			cnt++;
		s = s->next;
	}

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


	// choose a random server
	int cnt = count_active_servers();
	DnsServer *s = random_server();
	if (s == NULL)
		goto errout;

	while (s) {
		scurrent = s;
		if (arg_id == -1) { // testing only in frontend process
			uint8_t qaverage = test_server(s->name);
			if (qaverage == 0) {
				s->active = 0;
				s = random_server();
				continue;
			}
			else if (cnt > 1) {
				// try another server
				DnsServer *first = s;
				uint8_t first_average = qaverage;
				scurrent = first;
				s = first;
				if (first_average > SERVER_RESPONSE_LIMIT || s->keepalive_max < SERVER_KEEPALIVE_LIMIT) {
					// try another server if the first one responds in more than 70 ms
					// or if it has a keepalive under 110 seconds
					s = random_server();
					if (s == first) // try again
						s = random_server();
					scurrent = s;
					qaverage = test_server(s->name);
					// grab the fastest one
					if (qaverage == 0 || qaverage > first_average) {
						// revert back to the first server
						scurrent = first;
						s = first;
					}
				}
			}
		}
		// else - no testing in the resolver processes

		free(arg_server);
		arg_server = strdup(s->name);
		if (!arg_server)
			errExit("strdup");
		return scurrent;
	}


errout:
	fprintf(stderr, "Error: cannot connect to server %s\n", arg_server);
	exit(1);
}

void server_test_tag(const char *tag)  {
	if (tag && strcmp(tag, "admin-down") == 0)
		admin_down = 1;
	server_list(tag);

	// walk the list
	DnsServer *s = slist;
	while (s) {
		if (s->active) {
			scurrent = s;
			if (!s->transport) {
				if (s->transport)
					arg_transport = s->transport;
				else
					arg_transport = NULL;
			}

			test_server(s->name);
			usleep(500000);
		}
		s = s->next;
	}

	printf("\nTesting completed\n");
}

// todo: support for tls://dns.quad9.net    tls://1.1.1.1    tls://dot1.applied-privacy.net   tls://dns.adguard.com   tls://dns-family.adguard.com
// tls://dns.google
// todo: test --server and --test-server
void server_set_custom(const char *url) {
	set_zone();
	slist = malloc(sizeof(DnsServer));
	if (!slist)
		errExit("malloc");
	memset(slist, 0, sizeof(DnsServer));

	DnsServer *s = slist;
	if (strncmp(url, "https://", 8) == 0)
		s->host = strdup(url + 8); // skip https://
	else if (strncmp(url, "dot://", 6)  == 0) {
		s->host = strdup(url + 6); // skip dot://
		if (arg_transport == NULL)
			arg_transport = "dot";
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
		if (arg_transport && strcmp(arg_transport, "dot") == 0) {
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
	s->zone = "unknown";
	s->test_sni = 1;
	if (arg_keepalive) {
		s->keepalive_min = arg_keepalive;
		s->keepalive_max = arg_keepalive;
	}
	else {
		s->keepalive_min = 60;
		s->keepalive_max = 60;
	}

	s->transport = arg_transport;
	scurrent = s;
}

DnsServer *server_fallback_get(void) {
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
		0x6d, 0x00, 0x00, 0x02, 0x00, 0x01
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
