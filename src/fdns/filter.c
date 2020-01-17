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

// debug statistics
//#define DEBUG_STATS
#ifdef DEBUG_STATS
static unsigned smem = 0;	// memory
static unsigned sentries = 0;	// entries
static unsigned scnt = 0;	// search counter
static double stime = 0;		// accumulated search access time
#endif

static inline const char *label2str(char label) {
	if (label == 'A')
		return "ad";
	else if (label == 'T')
		return "tracker";
	else if (label == 'F')
		return "fp-tracker"; // first-party tracker
	else if (label == 'M')
		return "miner";
	else if (label == 'H')
		return "hosts";
	else if (label == 'R')
		return "reserved";

	return "?";
}

// default filter
typedef struct dfilter_t {
	char label;
	// Match based on the first letter:
	//      ^ - start of domain name
	//      $ - end of domain name
	//      regular letter: anywhere in the domain name
	char *name;
	int len;	// name string length
} DFilter;

// todo: add length field to speed up search
static DFilter default_filter[] = {
	// reserved domain names (RFC 2606, RFC 6761, RFC 6762)
	// - currently we are returning 127.0.0.1 regardless what RFC says
	// - RFC 6762: send .local to link-local multicast address 224.0.0.251 (todo)
	{'R', "$.local"},
	{'R', "$.localhost"},
	{'R', "$.test"},
	{'R', "$.invalid"},
	{'R', "$.example"},
	{'R', "$example.com"},
	{'R', "$example.net"},
	{'R', "$example.org"},

	{'A', "^ad."},
	{'A', "^ads."},
	{'A', "^adservice."},
	{'A', "^affiliate."},
	{'A', "^affiliates."},
	{'A', "^banner."},
	{'A', "^banners."},
	{'A', "click."},
	{'A', "clicks."},
	{'A', "collector."},
	{'A', "^creatives."},
	{'A', "id.google."},
	{'A', "^oas."},
	{'A', "^oascentral."},
	{'T', "^stats."},
	{'T', "^tag."},

	{'A', ".ad."},
	{'A', ".ads."},
	{'A', "admob."},
	{'A', "adserver"},
	{'A', "advertising"},
	{'T', "analytic."},
	{'T', "analytics."},
	{'T', "click."},
	{'T', "clickstatsview."},
	{'T', "counter."},
	{'T', "tags."},
	{'T', "tracking."},
//	"tracker.",	used by bittorrent trackers
	{'T', "telemetry."},
	{'T', "pixel."},

	// minimize first-party trackers list
	{'F', "^somniture."}, // 30
	{'F', "^aa-metrics."}, // 20
	{'F', "^smetric."}, //  2711
	{'F', "^smetrics."}, //  2642
	{'F', "^tr."}, // 1756
	{'F', "^metric."}, // 950
	{'F', "^metrics."}, // 644
	{'F', "^mdws."}, // 193
	{'F', "^srepdata."}, // 200
	{'F', "^marketing.net."}, // 66
	{'F', ".ati-host.net."},  // 91
	{'F', "^sadbmetrics."}, // 67
	{'F', "^somni."}, // 198
	{'F', "^srepdata,"}, //198
	{'F', "^sstats."}, // 339
	{'F', "^sw88."}, // 63
	{'F', "^tk.airfrance."}, // 98

	{0, NULL}
};

typedef struct hash_entry_t {
	struct hash_entry_t *next;
	char label;
	char *name;
} HashEntry;

#define MAX_HASH_ARRAY 32768
static HashEntry *blist[MAX_HASH_ARRAY];

void filter_init(void) {
	int i = 0;
	while (default_filter[i].name != NULL) {
		int offset = 0;
		if (*default_filter[i].name == '^' || *default_filter[i].name == '$')
			offset = 1;
		default_filter[i].len = strlen(default_filter[i].name + offset);
		i++;
	}
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

static void blist_add(char label, const char *domain) {
	assert(domain);
	HashEntry *h = malloc(sizeof(HashEntry));
	if (!h)
		errExit("malloc");
	h->label = label;
	h->name = strdup(domain);
	if (!h->name)
		errExit("strdup");

	int hval = hash(domain);
	assert(hval < MAX_HASH_ARRAY);
	h->next = blist[hval];
	blist[hval] = h;

#ifdef DEBUG_STATS
	smem += sizeof(HashEntry) + strlen(domain) + 1;
	sentries++;
#endif
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


static void filter_load_list(char label, const char *fname) {
	assert(fname);
	FILE *fp = fopen(fname, "r");
	if (!fp)
		return;  // nothing to do

	int test_hosts = 0;
	if (arg_test_hosts && strcmp(fname,PATH_ETC_HOSTS_LIST) == 0)
		test_hosts = 1;

	if (arg_print_drop_lists) {
		printf("\n\n");
		printf("//************************************************\n");
		printf("// file: %s\n", fname);
		printf("//************************************************\n");
	}

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

		ptr =strchr(buf, '#');
		if (ptr)
			*ptr = '\0';

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
		if (!filter_blocked(ptr, 0)) {
			if (arg_print_drop_lists || test_hosts) {
				// if the name starts in www,. remove it
				if (strncmp(ptr, "www.", 4) == 0)
					ptr += 4;
				printf("127.0.0.1 %s\n", ptr);
			}
			blist_add(label, ptr);
			cnt++;
		}
	}
	fclose(fp);

	if (arg_id == 0)
		printf("%d filter entries added from %s\n", cnt, fname);
}

void filter_load_all_lists(void) {
	filter_load_list('T', PATH_ETC_TRACKERS_LIST);
	filter_load_list('F', PATH_ETC_FP_TRACKERS_LIST);
	filter_load_list('A', PATH_ETC_ADBLOCKER_LIST);
	filter_load_list('M', PATH_ETC_COINBLOCKER_LIST);
	filter_load_list('H', PATH_ETC_HOSTS_LIST);
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
const char *filter_blocked(const char *str, int verbose) {
#ifdef DEBUG_STATS
	timetrace_start();
#endif
	int dlen = strlen(str); // todo: pass the length as function param
	int i = 0;

	// remove "www."
	if (strncmp(str, "www.", 4) == 0)
		str += 4;

	// check the default list
	while (default_filter[i].name != NULL) {
		if (*default_filter[i].name == '^') {
			int flen = default_filter[i].len;
			if (strncmp(str, default_filter[i].name + 1, flen) == 0) {
				if (verbose)
					printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i].name);
				return label2str(default_filter[i].label);
			}
		}
		else if (*default_filter[i].name == '$') {
			int flen = default_filter[i].len;
			if (strcmp(str + dlen - flen, default_filter[i].name + 1) == 0) {
				if (verbose)
					printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i].name);
				return label2str(default_filter[i].label);
			}
		}
		else  if (strstr(str, default_filter[i].name)) {
			if (verbose)
				printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i].name);
			return label2str(default_filter[i].label);
		}
		i++;
	}


	int cnt = extract_domains(str);
	for (i = cnt; i >= 0; i--) {
		HashEntry *ptr = blist_search(domain[i]);
		if (ptr) {
			if (verbose)
				printf("URL %s dropped by \"%s\" rule as a %s\n", str, ptr->name, label2str(ptr->label));
			return label2str(ptr->label);
		}
	}

	if (verbose)
		printf("URL %s is not dropped\n", str);

#ifdef DEBUG_STATS
	stime += timetrace_end();
	scnt++;
	if (scnt >= 20) {
		printf("*** filter entries %u, mem %u, access %.03f ms\n", sentries, smem + (unsigned) sizeof(blist), stime / scnt);
		fflush(0);
		stime = 0;
		scnt = 0;
	}
#endif

	return NULL;
}

void filter_test(char *url) {
	assert(url);

	char *ptr = strtok(url, ",");
	while (ptr) {
		filter_blocked(ptr, 1);
		ptr = strtok(NULL, ",");
	}
}
