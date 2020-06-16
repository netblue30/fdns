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
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <assert.h>

#define errExit(msg)    do { char msgout[500]; snprintf(msgout, 500, "Error %s: %s:%d %s", msg, __FILE__, __LINE__, __FUNCTION__); perror(msgout); exit(1);} while (0)

#define DEFAULT_THREADS 6
#define DEFAULT_THREADS_MIN 1
#define DEFAULT_THREADS_MAX 100
int arg_threads = DEFAULT_THREADS;
int arg_debug = 0;
char *arg_domain_list = NULL;

#define MAX_BUF 1024

//******************************************************************
// Domain list
//******************************************************************
typedef struct dlist_entry_t {
	struct dlist_entry_t *next;
	char *domain;
	volatile int done;
} DListEntry;

DListEntry *dlist = NULL;
void dlist_read(const char *fname) {
	assert(fname);
	char buf[MAX_BUF];

	FILE *fp = fopen(fname, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot open %s\n", fname);
		exit(1);
	}

	DListEntry *last = NULL;
	while (fgets(buf, MAX_BUF, fp)) {
		// cleanup
		char *start = buf;
		while (*start == ' ' || *start == '\t')
			start++;
		char *end = strchr(start, '\n');
		if (end)
			*end = '\0';

		// build the entry
		DListEntry *dptr = malloc(sizeof(DListEntry));
		if (!dptr)
			errExit("malloc");
		memset(dptr, 0, sizeof(DListEntry));
		dptr->domain = strdup(start);
		if (!dptr->domain)
			errExit("strdup");

		// is this the first element?
		if (!dlist) {
			dlist = dptr;
			last = dptr;
			continue;
		}

		// add the entry at the end of the list
		assert(last);
		last->next = dptr;
		last = dptr;
	}

	fclose(fp);
	if (!dlist) {
		fprintf(stderr, "Error: the domain list is empty!!!\n");
		exit (1);
	}
}

void dlist_print(void) {
	DListEntry *ptr = dlist;
	assert(ptr);

	while (ptr) {
		printf("%s\n", ptr->domain);
		ptr = ptr->next;
	}
}


//******************************************************************
// worker threads
//******************************************************************


static DListEntry *rq_send(DListEntry *ptr) {
	int i, rv;
	struct gaicb *reqs[DEFAULT_THREADS_MAX];
	char host[NI_MAXHOST];
	struct addrinfo *res;

	int cnt = 0;
	for (i = 0; i < arg_threads && ptr; i++) {
		reqs[i] = malloc(sizeof(*reqs[0]));
		if (!reqs[i])
			errExit("malloc");
		memset(reqs[i], 0, sizeof(*reqs[0]));
		reqs[i]->ar_name = ptr->domain;
		cnt++;
		ptr = ptr->next;
	}

	rv = getaddrinfo_a(GAI_WAIT, reqs, cnt, NULL);
	if (rv)
		errExit("getaddrinfo_a");

	for (i = 0; i < cnt; i++) {
		printf("%s: ", reqs[i]->ar_name);
		rv = gai_error(reqs[i]);
		if (rv == 0) {
			res = reqs[i]->ar_result;
			rv = getnameinfo(res->ai_addr, res->ai_addrlen,
					  host, sizeof(host),
					  NULL, 0, NI_NUMERICHOST);
			if (rv != 0) {
				fprintf(stderr, "getnameinfo() failed: %s\n",
					gai_strerror(rv));
				exit(EXIT_FAILURE);
			}
			puts(host);

		}
		else {
			puts(gai_strerror(rv));
			printf("retrying\n");
			// sleep and try again
			sleep(2);

			printf("%s: ", reqs[i]->ar_name);
			rv = gai_error(reqs[i]);
			(void) rv;
			rv = getaddrinfo_a(GAI_WAIT, reqs + i, 1, NULL);
			if (rv)
				errExit("getaddrinfo_a");
			if (rv == 0) {
				res = reqs[i]->ar_result;
				rv = getnameinfo(res->ai_addr, res->ai_addrlen,
						  host, sizeof(host),
						  NULL, 0, NI_NUMERICHOST);
				if (rv != 0) {
					fprintf(stderr, "getnameinfo() failed: %s\n",
						gai_strerror(rv));
					exit(EXIT_FAILURE);
				}
				puts(host);

			}
			else
				puts(gai_strerror(rv));

		}
	}

	return ptr;
}

static void rq_engine(void) {
	assert(dlist);

	DListEntry *ptr = dlist;
	while (ptr) {
		usleep(500000);
		ptr = rq_send(ptr);
	}
}



//******************************************************************
// main
//******************************************************************
	static void usage(void) {
	printf("fdnstress - DNS stress tool\n");
	printf("Usage: fdnstress [OPTIONS] domain-list\n");
	printf("    --debug - print debug messages.\n");
	printf("    --help, -? - this help screen.\n");
	printf("    --threads=number - number of threads, default %d.\n", DEFAULT_THREADS);
	printf("    --version - print program version and exit.\n");
}


int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Error: invalid number of arguments\n");
		usage();
		return 1;
	}

	int i;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 ||
		    strcmp(argv[i], "-?") == 0) {
			usage();
			return 0;
		}
		else if (strcmp(argv[i], "--version") == 0) {
			printf("fdnstress version %s\n", VERSION);
			return 0;
		}
		// extract domain list filename
		else if (i == (argc - 1)) {
			if (access(argv[i], R_OK) == -1) {
				fprintf(stderr, "Error: cannot access domain list file %s\n", argv[i]);
				return 1;
			}
			arg_domain_list = strdup(argv[i]);
			if (!arg_domain_list)
				errExit("strdup");
			break;
		}

		// deal with all the others options
		if (strcmp(argv[i], "--debug") == 0)
			arg_debug = 1;
		else if (strncmp(argv[i], "--threads=", 10) == 0) {
			arg_threads = atoi(argv[i] + 10);
			if (arg_threads < DEFAULT_THREADS_MIN || arg_threads > DEFAULT_THREADS_MAX) {
				fprintf(stderr, "Error: invalid number of threads, please provide a number between %d and %d\n",
					DEFAULT_THREADS_MIN, DEFAULT_THREADS_MAX);
				exit(1);
			}
		}
		else {
			fprintf(stderr, "Error: invalid command line argument %s\n", argv[i]);
			usage();
			return 1;
		}
	}

	// read domain list
	assert(arg_domain_list);
	dlist_read(arg_domain_list);
	if (arg_debug)
		dlist_print();

	// start the DNS requests
	rq_engine();

	return 0;
}
