/*
 * Copyright (C) 2019-2025 FDNS Authors
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
#include <ctype.h>

// debug statistics
//#define DEBUG_STATS
#ifdef DEBUG_STATS
static unsigned stats_mem = 0;	// memory
static unsigned stats_entries = 0;	// entries
static unsigned stats_cnt = 0;	// print counter
static double stats_time = 0;		// accumulated search access time
#endif

// default filter
typedef struct dfilter_t {
	// Match based on the first letter:
	//      ^ - start of domain name
	//      $ - end of domain name
	//      regular letter: anywhere in the domain name
	char *name;
	char *exception;	// false match if exception string inside name (strstr)
	int len;	// name string length
} DFilter;

// todo: add length field to speed up search
static DFilter default_filter[] = {
	// reserved domain names (RFC 2606, RFC 6761, RFC 6762)
	// - currently we are returning 127.0.0.1 regardless what RFC says
	// - RFC 6762: send .local to link-local multicast address 224.0.0.251 (todo)
	{"$.local", NULL, 0},
	{"$.localhost", NULL, 0},
	{"$.test", NULL, 0},
	{"$.invalid", NULL, 0},
	{"$.example", NULL, 0},
	{"$example.com", NULL, 0},
	{"$example.net", NULL, 0},
	{"$example.org", NULL, 0},

	{"^ad.", NULL, 0},
	{"^ads.", NULL, 0},
	{"^ads-", NULL, 0},
	{"^adservice.", NULL, 0},
	{"^affiliate.", NULL, 0},
	{"^affiliates.", NULL, 0},
	{"^banner", NULL, 0},
	{"banner.", NULL, 0},
	{"^banners", NULL, 0},
	{"banners.", NULL, 0},
	{"click.", NULL, 0},
	{"^click-", NULL, 0},
	{"clicks.", NULL, 0},
	{"^clicks-", NULL, 0},
	{"collector.", NULL, 0},
	{"^creatives.", NULL, 0},
	{"id.google.", NULL, 0},
	{"^oas.", NULL, 0},
	{"^oascentral.", NULL, 0},
//	{"^stats.", NULL, 0},
	{"^tag.", NULL, 0},
	{"^hostmaster.hostmaster", NULL, 0},

	{".ad.", ".ad.jp", 0},	// .ad.jp is popular Japanese domain
	{".ads.", NULL, 0},
	{"admob.", NULL, 0},
	{"adserver", NULL, 0},
	{"advertising", NULL, 0},
	{"analytic.", NULL, 0},
	{"analytics.", NULL, 0},
	{"click.", NULL, 0},
	{"clickstatsview.", NULL, 0},
	{"counter.", NULL, 0},
	{"tags.", NULL, 0},
	{"tracking.", NULL, 0},
//	"tracker.",	used by bittorrent trackers
	{"telemetry.", NULL, 0},
	{"pixel.", NULL, 0},

	// minimize first-party trackers list
	{"$metric.gstatic.com", NULL, 0}, // Google first-party tracker
	{"^somniture.", NULL, 0}, // 30
	{"^aa-metrics.", NULL, 0}, // 20
	{"^smetric.", NULL, 0}, //  2711
	{"^smetrics.", NULL, 0}, //  2642
	//	{"^tr.", NULL, 0}, // 1756 - lots of false positives, such as tr.wiktionary.org
	{"^metric.", NULL, 0}, // 950
	{"^metrics.", NULL, 0}, // 644
	{"^mdws.", NULL, 0}, // 193
	{"^srepdata.", NULL, 0}, // 200
	{"^marketing.net.",NULL,  0}, // 66
	{".ati-host.net.", NULL, 0},  // 91
	{"^sadbmetrics.", NULL, 0}, // 67
	{"^somni.", NULL, 0}, // 198
	{"^srepdata,", NULL, 0}, //198
	{"^sstats.", NULL, 0}, // 339
	{"^sw88.", NULL, 0}, // 63
	{"^tk.airfrance.", NULL, 0}, // 98

	{"^xinchao", NULL, 0}, // about 2800 miners here!
	{NULL, NULL, 0}	// last entry
};

//************************************
// CNAME cloaking based on rx DoH packet
//************************************
// based on https://github.com/nextdns/cname-cloaking-blocklist/blob/master/domains
// MIT license
static char *fp_block[] = {
	".eulerian",		//eulerian.net
	".at-o", 		//at-o.net
	".keyade.", 		//k.keyade.com
	".madmetrics",	// k.madmetrics.com
	".2o7.",		//2o7.net
	".adobedc.", 	// several domains
	".omtrdc.", 		//sc.omtrdc.net
	".storetail.",		//storetail.io
	".dnsdelegation.",	//dnsdelegation.io
	".tagcommander.",	//tagcommander.com
	".wizaly.",		//wizaly.com
	".affex.",		//affex.org
	".intentmedia.",	//partner.intentmedia.net
	".webtrekk.",	//webtrekk.net
	".wt-eu02.",		//wt-eu02.net
	".oghub.",		//oghub.io

	NULL
};

typedef struct hash_entry_t {
	struct hash_entry_t *next;
	unsigned short hash2;
	unsigned short file_id;
	unsigned line_no;
	char *name;
} HashEntry; //6258134

#define MAX_HASH_ARRAY 65536
static HashEntry *blist[MAX_HASH_ARRAY] = {NULL};
#define MAX_TLD_STR 2048
static char tlds[MAX_TLD_STR] = {'\0'};
#define MAX_FILE_ID 128
#define FILE_ID_INVALID 0xffff
static char *file_id_arr[MAX_FILE_ID] = {NULL};
static int file_id_cnt = 0;

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
static inline int hash(const char *str, unsigned short *hash2) {
	uint32_t hash = 5381;
	int c;

	while ((c = *str++) != '\0')
		hash = ((hash << 5) + hash) ^ c; // hash * 33 ^ c

	*hash2 = hash % 39119;
	return (int) (hash & (MAX_HASH_ARRAY - 1));
}


static void filter_add(const char *domain, unsigned short file_id, unsigned line_no) {
	assert(domain);
	if (arg_id == 0 && strchr(domain, '.') == NULL) {
		if (strlen(domain) < 10 && strlen(tlds) < (MAX_TLD_STR - 15)) {
			strcat(tlds, domain);
			strcat(tlds, ", ");
		}
	}

	HashEntry *h = malloc(sizeof(HashEntry));
	if (!h)
		errExit("malloc");
	h->name = strdup(domain);
	if (!h->name)
		errExit("strdup");
	h->file_id = file_id;
	h->line_no = line_no;

	int hval = hash(domain, &h->hash2);
	assert(hval < MAX_HASH_ARRAY);
	h->next = blist[hval];
	blist[hval] = h;

#ifdef DEBUG_STATS
	stats_mem += sizeof(HashEntry) + strlen(domain) + 1;
	stats_entries++;
#endif
}

static HashEntry *filter_search(const char *domain) {
	assert(domain);
	unsigned short hash2;
	int hval = hash(domain, &hash2);
	assert(hval < MAX_HASH_ARRAY);
	HashEntry *ptr = blist[hval];

	while (ptr) {
		if (hash2 == ptr->hash2) {
			if (strcmp(domain, ptr->name) == 0)
				return ptr; // found
		}
		ptr = ptr->next;
	}

	return NULL; // not found
}

void filter_load_list(const char *fname) {
	assert(fname);
	FILE *fp = fopen(fname, "r");
	if (!fp) {
		if (arg_id == 0) {
			fprintf(stderr, "Error: cannot open %s\n", fname);
			fprintf(stderr, "If AppArmor is enabled, please place the file in %s directory\n", SYSCONFDIR);
		}
		return;
	}

	unsigned short file_id = file_id_cnt;
	if (file_id < MAX_FILE_ID) {
		file_id_arr[file_id] = strdup(fname);
		if (!file_id_arr[file_id])
			errExit("strdup");
		file_id_cnt++;

	}
	else
		file_id = FILE_ID_INVALID;

	char buf[MAXBUF];
	int cnt = 0;
	int removed = 0;
	int line_no = 0;
	while (fgets(buf, MAXBUF, fp)) {
		line_no++;
		// remove \n
		char *ptr = strstr(buf, "\n");
		if (ptr)
			*ptr = '\0';

		// comments, empty lines
		if (*buf == '#' || *buf == '\0' || strspn(buf, " \t") == strlen(buf))
			continue;

		ptr = strchr(buf, '#');
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
		if (!filter_blocked(ptr, 0, 0)) {
			filter_add(ptr, file_id, line_no);
			cnt++;
		}
		else
			removed++;
	}
	fclose(fp);

	fflush(0);
	if (arg_id == 0)
		printf("%s: %d domains added, %d removed\n", fname, cnt, removed);
}

void filter_load_all_lists(void) {
	// apparmor will fail glob() or opendir() on /etc/fdns directory
	// we need to hardcode the filter files!

	// global filters developed by fdns project
	filter_load_list(PATH_ETC_TLD_LIST);
	filter_load_list(PATH_ETC_PHISHING_LIST);
	filter_load_list(PATH_ETC_DYNDNS_LIST);

	// independent filters developed by various other projects
	filter_load_list(PATH_ETC_COINBLOCKER_LIST);
	filter_load_list(PATH_ETC_MALWARE_LIST);
	filter_load_list(PATH_ETC_TRACKERS_LIST);
	filter_load_list(PATH_ETC_ADBLOCKER_LIST);

	// personal filters
	filter_load_list(PATH_ETC_HOSTS_LIST);

	int i;
	for (i = 0; i < MAX_BLOCKLIST_FILE; i++) {
		if (arg_blocklist_file[i])
			filter_load_list(arg_blocklist_file[i]);
	}

	if (arg_id == 0)
		printf("\nThe following TLDs have been disabled: %s\n\n", tlds);
#ifdef DEBUG_STATS
	int max_cnt = 0;
	HashEntry *max_line = NULL;
	int zero_cnt = 0;
	int i;
	for (i = 0; i < MAX_HASH_ARRAY; i++) {
		int cnt = 0;
		HashEntry *ptr = blist[i];
		if (!ptr)
			zero_cnt++;
		while (ptr) {
			cnt++;
			ptr = ptr->next;
		}

		if (cnt > max_cnt) {
			max_cnt = cnt;
			max_line = blist[i];
		}
	}

	printf("*** %u filter entries, total memory %lu\n", stats_entries, stats_mem + sizeof(blist));
	printf("*** htable empty lines %d\n", zero_cnt);
	printf("*** max htable line %d\n", max_cnt);
	printf("*** max line hash2 values: ");
	while (max_line) {
		printf("%u, ", max_line->hash2);
		max_line = max_line->next;
	}
	printf("\n");
#endif
}

#define MAX_DOMAINS 64
static const char *domains[MAX_DOMAINS];
static int extract_domains(const char *ptr) {
	assert(ptr);

	domains[0] = ptr;
	int i = 1;

	while (*ptr) {
		if (*ptr == '.') {
			domains[i] = ptr + 1;
			if (++i >= MAX_DOMAINS)
				return i - 1;
		}
		ptr++;
	}

	domains[i] = NULL;
	return i - 1;
}
void clear_domains(void) {
	int i;
	for (i = 0; i < MAX_DOMAINS; i++)
		domains[i] = NULL;
}


// ibm silerpor trackers
// examples; mkt9611.com, mkt9612.com, mkt9613.com
// return 1 if a silverpop domain
static inline int silverpop(const char *str) {
	if (strncmp(str, "mkt", 3))
		return 0;
	const char *ptr = str + 3;
	while (isdigit(*ptr))
		ptr++;
	if(strcmp(ptr, ".com") == 0)
		return 1;
	return 0;
}

// 025gmail.com
// 000006138.com
static inline int numbersdot(const char *str) {
	if (!isdigit(*str))
		return 0;
	const char *ptr = str;
	while (isdigit(*ptr) || *ptr == '-')
		ptr++;
	if (strcmp(ptr, "gmail.com") == 0)
		return 1;
	else if (*ptr == '.') {
		ptr++;
		if (strchr(ptr, '.'))
			return 0;
		return 1;
	}
	return 0;
}

static int custom_checks(const char *str) {
	int rv = silverpop(str);
	if (rv)
		return rv;
	rv = numbersdot(str);
	if (rv)
		return rv;


	return 0;
}


// return 1 if the site is blocked, 0 if the site is not blocked
int filter_blocked(const char *str, int verbose, int default_check) {
#ifdef DEBUG_STATS
	timetrace_start();
#endif
	int dlen = strlen(str);

	// remove "www."
	if (strncmp(str, "www.", 4) == 0)
		str += 4;

	// custom checks
	int rv = custom_checks(str);
	if (rv) {
		if (verbose)
			printf("URL %s dropped by a custom rule\n", str);
		return rv;
	}

	// check the default list
	int i = 0;
	if (default_check) {
		while (default_filter[i].name != NULL) {
			if (*default_filter[i].name == '^') {
				int flen = default_filter[i].len;
				if (strncmp(str, default_filter[i].name + 1, flen) == 0) {
					// handle exceptions
					if (default_filter[i].exception && strstr(str, default_filter[i].exception))
						break;
					if (verbose)
						printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i].name);
					return 1;
				}
			}
			else if (*default_filter[i].name == '$') {
				int flen = default_filter[i].len;
				if (strcmp(str + dlen - flen, default_filter[i].name + 1) == 0) {
					if (default_filter[i].exception && strstr(str, default_filter[i].exception))
						break;
					if (verbose)
						printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i].name);
					return 1;
				}
			}
			else  if (strstr(str, default_filter[i].name)) {
				if (default_filter[i].exception && strstr(str, default_filter[i].exception))
					break;
				if (verbose)
					printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i].name);
				return 1;
			}
			i++;
		}
	}

	// check default fptrackers
	i = 0;
	while (fp_block[i]) {
		if (strstr(str, fp_block[i])) {
			if (verbose)
				printf("URL %s dropped by default fptrackers rule \"%s\"\n", str, fp_block[i]);
			return 1;
		}
		i++;
	}


	int cnt = extract_domains(str);
	for (i = cnt; i >= 0; i--) {
		HashEntry *ptr = filter_search(domains[i]);
		if (ptr) {
			clear_domains(); // remove scan-build warnings
			if (verbose) {
				if (ptr->file_id == FILE_ID_INVALID)
					printf("URL %s dropped by \"%s\" rule\n",
						str, ptr->name);
				else
					printf("URL %s dropped by \"%s\" rule (%s:%u)\n",
						str, ptr->name,
						file_id_arr[ptr->file_id], ptr->line_no);
			}
			return 1;
		}
	}
	clear_domains(); // remove scan-build warnings

	if (verbose)
		printf("URL %s is not dropped\n", str);

#ifdef DEBUG_STATS
	stats_time += timetrace_end();
	stats_cnt++;
	if (stats_cnt >= 10) {
		printf("\n*** average filter access %.03f ms\n\n", stats_time / stats_cnt);
		fflush(0);
		stats_time = 0;
		stats_cnt = 0;
	}
#endif

	return 0;
}

void filter_test(char *url) {
	assert(url);
	// skip http/https
	char *start = url;
	if (strncmp(start, "https://", 8) == 0)
		start += 8;
	else if (strncmp(start, "http://", 7) == 0)
		start += 7;

	char *ptr = strchr(start, '/');
	if (ptr)
		*ptr = 0;
	filter_blocked(start, 1, 1);
}


// supported formats:
//    - lines in regular hosts files with ip addresses of 127.0.0.1 and 0.0.0.0
//    - lists of domain names, one domain per line
void filter_test_list(void) {
	char buf[MAXBUF];
	while (fgets(buf, MAXBUF, stdin)) {
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		// comments
		char *start = ptr;
		if (*start == '#' || *start == '\0') // comment
			continue;
		ptr = strchr(start, '#');
		if (ptr)
			*ptr = '\0';

		// regular hosts files:
		// 127.0.0.1 domain.name
		if (strncmp(start, "127.0.0.1", 9) == 0)
			start += 9;
		else if (strncmp(start, "0.0.0.0", 7) == 0)
			start += 7;
		while (*start == ' ' || *start == '\t')
			start++;

		// clean end spaces
		ptr = strchr(start, ' ');
		if (ptr)
			*ptr = '\0';
		ptr = strchr(start, '\t');
		if (ptr)
			*ptr = '\0';

		// clean www.
		if (strncmp(start, "www.", 4) == 0)
			start += 4;
		if (*start == '\0')
			continue;
		if (strstr(start, "::")) // IPv6 addresses!
			continue;
		if (!filter_blocked(start, 0, 1))
			printf("127.0.0.1 %s\n", start);

#ifdef HAVE_GCOV
		__gcov_flush();
#endif
	}
}

