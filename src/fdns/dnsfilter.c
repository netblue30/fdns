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

	return "?";
}

// default filter
typedef struct dfilter_t {
	char label;
	char *name;
} DFilter;

static DFilter default_filter[] = {

	// start of name
	{'A', "$ad."},
	{'A', "$ads."},
	{'A', "$banner."},
	{'A', "$banners."},
	{'A', "$creatives."},
	{'A', "$oas."},
	{'A', "$oascentral."},
	{'T', "$stats."},
	{'T', "$tag."},

	// anywhere in the name
	{'A', ".ad."},
	{'A', ".ads."},
	{'A', "admob."},
	{'A', "adserver"},
	{'A', "advertising"},
	{'T', "analytics."},
	{'T', "click."},
	{'T', "clickstatsview."},
	{'T', "counter."},
	{'T', "tags."},
	{'T', "tracking."},
//	"tracker.",
	{'T', "telemetry."},
	{'T', "pixel."},

	// minimize first-party trackers list
	{'F', "$smetric."}, //  2711 on the original fp-trackers list
	{'F', "$smetrics."}, //  2642
	{'F', "$tr."}, // 1756
	{'F', "$metric."}, // 950
	{'F', "$metrics."}, // 644
	{'F', "$mdws."}, // 193
	{'F', "$marketing.net."}, // 66
	{'F', ".ati-host.net."},  // 91
	{'F', "$sadbmetrics."}, // 67
	{'F', "$somni."}, // 198
	{'F', "$srepdata,"}, //198
	{'F', "$sstats."}, // 339
	{'F', "$sw88."}, // 63
	{'F', "$tk.airfrance."}, // 98

	{0, NULL}
};

typedef struct hash_entry_t {
	struct hash_entry_t *next;
	char label;
	char *name;
} HashEntry;

#define MAX_HASH_ARRAY 16384  // 32768
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


static void dnsfilter_load_list(char label, const char *fname) {
	assert(fname);
	FILE *fp = fopen(fname, "r");
	if (!fp)
		return;  // nothing to do

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
			if (arg_print_drop_lists) {
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

void dnsfilter_load_all_lists(void) {
	dnsfilter_load_list('T', PATH_ETC_TRACKERS_LIST);
	dnsfilter_load_list('F', PATH_ETC_FP_TRACKERS_LIST);
	dnsfilter_load_list('A', PATH_ETC_ADBLOCKER_LIST);
	dnsfilter_load_list('M', PATH_ETC_COINBLOCKER_LIST);
	dnsfilter_load_list('H', PATH_ETC_HOSTS_LIST);
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
const char *dnsfilter_blocked(const char *str, int verbose) {
//timetrace_start();
	int i = 0;

	// check the default list
	while (default_filter[i].name != NULL) {
		if (*default_filter[i].name == '$') {
			if (strncmp(str, default_filter[i].name + 1, strlen(default_filter[i].name + 1)) == 0) {
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

//float ms = timetrace_end();
//printf(" (%.03f ms)\n", ms);
	return NULL;
}

void dnsfilter_test(char *url) {
	assert(url);

	char *ptr = strtok(url, ",");
	while (ptr) {
		dnsfilter_blocked(ptr, 1);
		ptr = strtok(NULL, ",");
	}
}
