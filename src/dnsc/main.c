/*
 * Copyright (C) 2019-2024 FDNS Authors
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

#include "dnsc.h"
#include <unistd.h>
#include <time.h>
#include <ctype.h>

char execpath[LINE_MAX+ 1];

static int arg_cnt = 0;
int arg_short = 0;
int arg_debug = 0;
static char *arg_dedup = NULL;

FILE *fpout = NULL;

static int total_domains = 0;
static int total_whitelisted = 0;
static int total_ipaddr = 0;
static int total_dedup = 0;
static int input_compression = 0;

Node *domains = NULL;
static Node *fast_search = NULL;

static void set_subs(Node *n) {
	assert(n);

	char *ptr = n->name + n->len - 1;
	int i;
	for (i = n->len  - 1; i > 0; i--, ptr--) {
		if (*ptr == '.') {
			if (n->s1 == NULL)
				n->s1 = ptr + 1;
			else if (n->s2 == NULL)
				n->s2 = ptr + 1;
			else if (n->s3 == NULL)
				n->s3 = ptr + 1;
			else if (n->s4 == NULL)
				n->s4 = ptr + 1;
		}
	}

	if (n->s1 == NULL)
		n->s1 = ptr;
	else if (n->s2 == NULL)
		n->s2 = ptr;
	else if (n->s3 == NULL)
		n->s3 = ptr;
	else if (n->s4 == NULL)
		n->s4 = ptr;
}

// return 1 if found; set fast_search to null to start from the beginning of the list
static Node *domain_find(const char *name) {
	assert(name);
	assert(*name != '\0');
	int len = strlen(name);

	Node *ptr = fast_search;
	if (!ptr)
		ptr = domains;

	while (ptr) {
		fast_search = ptr;
		int delta = len - ptr->len;
		if (delta == 0 && strcmp(name, ptr->name) == 0)
			return ptr;

		if (delta > 0 && strcmp(name + delta, ptr->name) == 0) {
			if (name[delta - 1] == '.')
				return ptr;
		}

		ptr = ptr->next;
	}

	return NULL;
}


static void domain_add(const char *name) {
	static Node  *last = NULL;
	if (!name)
		return;
	if (*name == '\0')
		return;

	Node *node = domain_find(name);
	if (node) {
		node->cnt++;
		return;
	}

	node = malloc(sizeof(Node));
	if (!node)
		errExit("malloc");
	memset(node, 0, sizeof(Node));
	node->name = strdup(name);
	if (!node->name)
		errExit("strdup");
	node->len = strlen(name);
	node->cnt = 1;
	node->next = NULL;
	if (last == NULL)
		domains = node;
	else
		last->next = node;
	last = node;
	set_subs(node);
}


static void load_files(int argc, char **argv, int index) {
	whitelist_load();
	while (index < argc) {
		rsort_load(argv[index]);
		index++;
	}
	char **sorted = rsort();

	int i = 0;
	while (sorted[i] != NULL) {
		total_domains++;

		// is this an IP address?
		char *ptr = sorted[i];
		while (isdigit(*ptr) || *ptr == '.')
			ptr++;
		if (*ptr == '\0') {
// printf("%s\n", sorted[i]);
			total_ipaddr++;
			goto endloop;
		}

		if (whitelist_find(sorted[i])) {
			total_whitelisted++;
			goto endloop;
		}

		if (dedup_search(sorted[i])) {
			total_dedup++;
			goto endloop;
		}


		input_compression++;
		domain_add(sorted[i]);
endloop:
		i++;
	}

	return;
}

static void print_stats(void) {
	if (arg_short) {
		printf("# Input list(s): %d domains\n", total_domains);
		subs_print(input_compression);
		exit(0);
	}

	// count final domains number
	int phishing = 0;
	Node *ptr = domains;
	while (ptr) {
		phishing++;
		ptr = ptr->next;
	}

	printf("\n");
	printf("# Input list(s): %d domains\n", total_domains);
	printf("#   removed %d (%.02f%%) IP addresses\n", total_ipaddr, ((double) total_ipaddr / (double) total_domains) * 100);
	printf("#   removed %d (%.02f%%) false positives\n", total_whitelisted, ((double) total_whitelisted / (double) total_domains) * 100);
	if (arg_dedup)
		printf("#   removed %d (%.02f%%) duplicates in dedup file\n", total_dedup, ((double) total_dedup / (double) total_domains) * 100);

	if (total_domains) {
		printf("# Final list: %d domains (input list compressed down to %0.02f%%)\n",
		       phishing, ((double) phishing / (double) total_domains) * 100);
		if (total_whitelisted)
			whitelist_print(total_domains);
	}

	printf("\n");
	printf("# Compressed list\n");
	ptr = domains;
	while (ptr) {
		printf( "127.0.0.1 %s\n", ptr->name);
		phishing++;
		ptr = ptr->next;
	}

	printf("\n");
	subs_print(input_compression);
	printf("\n");
}

int get_limit(void) {
	if (arg_cnt)
		return arg_cnt;
	double rv = (double) total_domains * 1 / 1000; // 0.1%
	if (rv < 1)
		rv = 1;
	return (int) rv;
}

static void usage(void) {
	printf("dnsc - utility program for cleaning and compressing wildcard domain lists\n");
	printf("\n");
	printf("Usage: dnsc [options] hosts-file [hosts-file]\n");
	printf("where:\n");
	printf("   hosts-file - DNS blocklist file in hosts format. All domains are considered\n");
	printf("                wildcard domains.\n");
	printf("\n");
	printf("Options:\n");
	printf("   --cnt=number - above this number, the domain is reported in the short list;\n");
	printf("                  by default we use 0.1%% of the number of input domains\n");
	printf("   --debug - print debug info\n");
	printf("   --dedup=file - remove duplicate found in file\n");
	printf("   -?, -h, --help - this help screen\n");
	printf("   --short - print the short list\n");
	printf("\n");
	printf("Note: Domains in /etc/hosts files on regular Linux computers ARE NOT WILDCARDS!\n");
	printf("A wildcard list installed in /etc/hosts will not work.\n");
	printf("\n");
}

int main(int argc, char **argv) {
	execpath[0] = '\0';
	ssize_t sz = readlink("/proc/self/exe", execpath, LINE_MAX);
	if (sz == -1)
		execpath[0] = '\0';
	else
		execpath[sz] = '\0';

	int i;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
			usage();
			return 0;
		}
		else if (strcmp(argv[i], "--debug") == 0)
			arg_debug = 1;
		else if (strcmp(argv[i], "--short") == 0)
			arg_short = 1;
		else if (strncmp(argv[i], "--dedup=", 8) == 0)
			arg_dedup = argv[i] + 8;
		else if (strncmp(argv[i], "--cnt=", 6) == 0)
			arg_cnt = atoi(argv[i] + 6);
		else if (*argv[i] == '-') {
			fprintf(stderr, "Error: invalid program argument\n");
			usage();
			return 1;
		}
		else
			break;
	}

	if (arg_debug)
		fprintf(stderr, "Executable path %s#\n", execpath);

	if (arg_dedup)
		dedup_init(arg_dedup);

	// generate stats
	if (i < argc) {
		load_files(argc, argv, i);
		print_stats();
	}
	else {
		fprintf(stderr, "Error: please provide a list file\n\n");
		usage();
		return 1;
	}

	return 0;
}
