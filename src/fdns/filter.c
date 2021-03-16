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

// debug statistics
//#define DEBUG_STATS
#ifdef DEBUG_STATS
static unsigned smem = 0;	// memory
static unsigned sentries = 0;	// entries
static unsigned scnt = 0;		// print counter
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
	else if (label == 'D')
		return "doh";
	else if (label == 'B')
		return "bulkmailer";

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
	char *exception;	// false match if exception inside name (strstr)
	int len;	// name string length
} DFilter;

// todo: add length field to speed up search
static DFilter default_filter[] = {
	// reserved domain names (RFC 2606, RFC 6761, RFC 6762)
	// - currently we are returning 127.0.0.1 regardless what RFC says
	// - RFC 6762: send .local to link-local multicast address 224.0.0.251 (todo)
	{'R', "$.local", NULL, 0},
	{'R', "$.localhost", NULL, 0},
	{'R', "$.test", NULL, 0},
	{'R', "$.invalid", NULL, 0},
	{'R', "$.example", NULL, 0},
	{'R', "$example.com", NULL, 0},
	{'R', "$example.net", NULL, 0},
	{'R', "$example.org", NULL, 0},

	{'A', "^ad.", NULL, 0},
	{'A', "^ads.", NULL, 0},
	{'A', "^adservice.", NULL, 0},
	{'A', "^affiliate.", NULL, 0},
	{'A', "^affiliates.", NULL, 0},
	{'A', "^banner.", NULL, 0},
	{'A', "^banners.", NULL, 0},
	{'A', "click.", NULL, 0},
	{'A', "clicks.", NULL, 0},
	{'A', "collector.", NULL, 0},
	{'A', "^creatives.", NULL, 0},
	{'A', "id.google.", NULL, 0},
	{'A', "^oas.", NULL, 0},
	{'A', "^oascentral.", NULL, 0},
	{'T', "^stats.", NULL, 0},
	{'T', "^tag.", NULL, 0},
	{'M', "^hostmaster.hostmaster", NULL, 0},

	{'A', ".ad.", ".ad.jp", 0},	// .ad.jp is popular Japanese domain
	{'A', ".ads.", NULL, 0},
	{'A', "admob.", NULL, 0},
	{'A', "adserver", NULL, 0},
	{'A', "advertising", NULL, 0},
	{'T', "analytic.", NULL, 0},
	{'T', "analytics.", NULL, 0},
	{'T', "click.", NULL, 0},
	{'T', "clickstatsview.", NULL, 0},
	{'T', "counter.", NULL, 0},
	{'T', "tags.", NULL, 0},
	{'T', "tracking.", NULL, 0},
//	"tracker.",	used by bittorrent trackers
	{'T', "telemetry.", NULL, 0},
	{'T', "pixel.", NULL, 0},

	// minimize first-party trackers list
	{'F', "$metric.gstatic.com", NULL, 0}, // Google first-party tracker
	{'F', "^somniture.", NULL, 0}, // 30
	{'F', "^aa-metrics.", NULL, 0}, // 20
	{'F', "^smetric.", NULL, 0}, //  2711
	{'F', "^smetrics.", NULL, 0}, //  2642
	{'F', "^tr.", NULL, 0}, // 1756
	{'F', "^metric.", NULL, 0}, // 950
	{'F', "^metrics.", NULL, 0}, // 644
	{'F', "^mdws.", NULL, 0}, // 193
	{'F', "^srepdata.", NULL, 0}, // 200
	{'F', "^marketing.net.",NULL,  0}, // 66
	{'F', ".ati-host.net.", NULL, 0},  // 91
	{'F', "^sadbmetrics.", NULL, 0}, // 67
	{'F', "^somni.", NULL, 0}, // 198
	{'F', "^srepdata,", NULL, 0}, //198
	{'F', "^sstats.", NULL, 0}, // 339
	{'F', "^sw88.", NULL, 0}, // 63
	{'F', "^tk.airfrance.", NULL, 0}, // 98
	{0, NULL, NULL, 0}	// last entry
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

void filter_add(char label, const char *domain) {
//if (label == 'M')
//printf("127.0.0.1 %s\n", domain);

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

static HashEntry *filter_search(const char *domain) {
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

void filter_serach_add(char label, const char *domain) {
	if (!filter_search(domain))
		filter_add(label, domain);
}

static void filter_load_list(char label, const char *fname, int store) {
	assert(fname);
	FILE *fp = fopen(fname, "r");
	if (!fp)
		return;  // nothing to do

	FILE *fpout = NULL;
	if (store) {
		char *f = strrchr(fname, '/');
		if (!f) {
			fprintf(stderr, "Error: invalid file name %s\n", fname);
			exit(1);
		}
		f++;
		fpout = fopen(f, "w");
		if (!fpout)
			errExit("fopen");
	}

	char buf[MAXBUF];
	int cnt = 0;
	while (fgets(buf, MAXBUF, fp)) {
		// remove \n
		char *ptr = strstr(buf, "\n");
		if (ptr)
			*ptr = '\0';

		// comments, empty lines
		if (*buf == '#' || *buf == '\0' || strspn(buf, " \t") == strlen(buf)) {
			if (store)
				fprintf(fpout, "%s\n", buf);
			continue;
		}

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
			if (store)
				fprintf(fpout, "127.0.0.1 %s\n", ptr);
			filter_add(label, ptr);
			cnt++;
		}
	}
	fclose(fp);
	if (store)
		fclose(fpout);

	fflush(0);
	if (arg_id == 0)
		printf("%d filter entries added from %s\n", cnt, fname);
}

void filter_load_all_lists(void) {
	filter_load_list('T', PATH_ETC_TRACKERS_LIST, arg_clean_filters);
	filter_load_list('F', PATH_ETC_FP_TRACKERS_LIST, arg_clean_filters);
	filter_load_list('A', PATH_ETC_ADBLOCKER_LIST, arg_clean_filters);
	filter_load_list('M', PATH_ETC_COINBLOCKER_LIST, arg_clean_filters);
	filter_load_list('H', PATH_ETC_HOSTS_LIST, arg_clean_filters);
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

// return NULL if the site is not blocked
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
				// handle exceptions
				if (default_filter[i].exception && strstr(str, default_filter[i].exception))
					break;
				if (verbose)
					printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i].name);
				return label2str(default_filter[i].label);
			}
		}
		else if (*default_filter[i].name == '$') {
			int flen = default_filter[i].len;
			if (strcmp(str + dlen - flen, default_filter[i].name + 1) == 0) {
				if (default_filter[i].exception && strstr(str, default_filter[i].exception))
					break;
				if (verbose)
					printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i].name);
				return label2str(default_filter[i].label);
			}
		}
		else  if (strstr(str, default_filter[i].name)) {
			if (default_filter[i].exception && strstr(str, default_filter[i].exception))
				break;
			if (verbose)
				printf("URL %s dropped by default rule \"%s\"\n", str, default_filter[i].name);
			return label2str(default_filter[i].label);
		}
		i++;
	}


	int cnt = extract_domains(str);
	for (i = cnt; i >= 0; i--) {
		HashEntry *ptr = filter_search(domains[i]);
		if (ptr) {
			clear_domains(); // remove scan-build warnings
			if (verbose)
				printf("URL %s dropped by \"%s\" rule as a %s\n", str, ptr->name, label2str(ptr->label));
			return label2str(ptr->label);
		}
	}
	clear_domains(); // remove scan-build warnings

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
	filter_blocked(url, 1);
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
		const char *str = filter_blocked(start, 0);
		if (!str)
			printf("127.0.0.1 %s\n", start);
	}
}

//************************************
// CNAME cloaking based on rx DoH packet
//************************************
static char *fp_block[] = {
	".eulerian",		//eulerian.net
	".at-o", 		//at-o.net
	".keyade.", 		//k.keyade.com
	".2o7.",		//2o7.net
	".omtrdc.", 		//sc.omtrdc.net
	".storetail.",		//storetail.io
	".dnsdelegation.",	//dnsdelegation.io
	".tagcommander.",	//tagcommander.com
	".wizaly.",		//wizaly.com
	".a88045584548111e997c60ac8a4ec150-1610510072.",
		//a88045584548111e997c60ac8a4ec150-1610510072.eu-central-1.elb.amazonaws.com
	".afc4d9aa2a91d11e997c60ac8a4ec150-2082092489.",
		//afc4d9aa2a91d11e997c60ac8a4ec150-2082092489.eu-central-1.elb.amazonaws.com
	".affex.",		//affex.org
	".intentmedia.",	//partner.intentmedia.net
	".webtrekk.",	//webtrekk.net
	".wt-eu02.",		//wt-eu02.net
	".oghub.",		//oghub.io
	NULL
};

// return -1 if found in the block list, 0 if not found in the block list
int filter_cname(const char *cname) {
	assert(cname);
	int i = 0;

	while (fp_block[i]) {
		if (strstr(cname, fp_block[i]))
			return -1;
		i++;
	}

	return 0;
}
