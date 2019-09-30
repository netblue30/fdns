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


static char *default_filter[] = {

	// start of name
	"$ad.",
	"$ads.",
	"$banner.",
	"$banners.",
	"$creatives.",
	"$oas.",
	"$oascentral.",
	"$stats.",
	"$tag.",

	// anywhere in the name
	".ad.",
	".ads."
	"admob.",
	"adserver",
	"advertising",
	"analytics.",
	"click.",
	"clickstatsview.",
	"counter.",
	"tags.",
	"tracking.",
//	"tracker.",
	"telemetry."
	"pixel.",
	NULL
};

typedef struct hash_entry_t {
	struct hash_entry_t *next;
	char *name;
} HashEntry;

#define MAX_HASH_ARRAY 4096
static HashEntry *blist[MAX_HASH_ARRAY];

void dnsfilter_init(void) {
	memset(&blist[0], 0, sizeof(blist));
}

// djb2 hash function by Dan Bernstein
static inline int hash(const char *str) {
	uint32_t hash = 5381;
	int c;

	while ((c = *str++) != '\0')
		hash = ((hash << 5) + hash) ^ c; // hash * 33 ^ c

	return (int) (hash & (MAX_HASH_ARRAY - 1));
}

static void blist_add(const char *domain) {
	assert(domain);
	HashEntry *h = malloc(sizeof(HashEntry));
	if (!h)
		errExit("malloc");
	h->name = strdup(domain);
	if (!h->name)
		errExit("strdup");

	int hval = hash(domain);
	assert(hval < MAX_HASH_ARRAY);
	h->next = blist[hval];
	blist[hval] = h;
}

static HashEntry *blist_search(const char *domain) {
	assert(domain);
	int hval = hash(domain);
	assert(hval < MAX_HASH_ARRAY);
	HashEntry *ptr = blist[hval];

	while (ptr) {
		if (strcmp(domain, ptr->name) == 0)
			return ptr; // found
		ptr = ptr->next;
	}

	return NULL; // not found
}


void dnsfilter_load_list(const char *fname) {
	assert(fname);
	FILE *fp = fopen(fname, "r");
	if (!fp)
		return;  // nothing to do

	char buf[MAXBUF];
	int cnt = 0;
	while (fgets(buf, MAXBUF, fp)) {
		// remove \n
		char *ptr = strstr(buf, "\n");
		if (ptr)
			*ptr = '\0';

		// comments, empty lines
		if (*buf == '#' || *buf == '\0' || strspn(buf, " \t") == strlen(buf))
			continue;

		// remove blanks
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		// adding lines starting with 0.0.0.0 or 127.0.0.1
		if (strncmp(ptr, "0.0.0.0", 7) == 0)
			ptr += 7;
		else if (strncmp(ptr, "127.0.0.1", 9) == 0)
			ptr += 9;
		else
			continue;


		// remove localhost etc
		if (strstr(ptr, "local"))
			continue;

		// remove blanks
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;
		char *ptr2 = strchr(ptr, ' ');
		if (ptr2)
			*ptr2 = '\0';
		ptr2 = strchr(ptr, '\t');
		if (ptr2)
			*ptr2 = '\0';

		// add it to the hash table
		if (!dnsfilter_blocked(ptr, 0)) {
			blist_add(ptr);
			cnt++;
		}
	}
	fclose(fp);

	if (arg_id == 0)
		printf("%d filter entries added from %s\n", cnt, fname);

}


#define MAX_DOMAINS 64
static const char *domain[MAX_DOMAINS];
static int extract_domains(const char *ptr) {
	assert(ptr);

	domain[0] = ptr;
	int i = 1;

	while (*ptr) {
		if (*ptr == '.') {
			domain[i] = ptr + 1;
			if (++i >= MAX_DOMAINS)
				return i - 1;
		}
		ptr++;
	}

	domain[i] = NULL;
	return i - 1;
}

// return 1 if the site is blocked
int dnsfilter_blocked(const char *str, int verbose) {
//timetrace_start();
	int i = 0;

	// check the default list
	while (default_filter[i] != NULL) {
		if (*default_filter[i] == '$') {
			if (strncmp(str, default_filter[i] + 1, strlen(default_filter[i] + 1)) == 0) {
				if (verbose)
					printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i]);
				return 1;
			}
		}
		else  if (strstr(str, default_filter[i])) {
			if (verbose)
				printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i]);
			return 1;
		}
		i++;
	}


	int cnt = extract_domains(str);
	for (i = cnt; i >= 0; i--) {
		HashEntry *ptr = blist_search(domain[i]);
		if (ptr) {
			if (verbose)
				printf("URL %s dropped by \"%s\" rule\n", str, ptr->name);
			return 1;
		}
	}

	if (verbose)
		printf("URL %s is not dropped\n", str);
//float ms = timetrace_end();
//printf(" (%.03f ms)\n", ms);
	return 0;
}

void dnsfilter_test(char *url) {
	assert(url);

	char *ptr = strtok(url, ",");
	while (ptr) {
		dnsfilter_blocked(ptr, 1);
		ptr = strtok(NULL, ",");
	}
}
