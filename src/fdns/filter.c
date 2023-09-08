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
 #include <ctype.h>

// debug statistics
//#define DEBUG_STATS
#ifdef DEBUG_STATS
static unsigned stats_mem = 0;	// memory
static unsigned stats_entries = 0;	// entries
static unsigned stats_cnt = 0;	// print counter
static double stats_time = 0;		// accumulated search access time
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
	else if (label == 'P')
		return "phishing";

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
	{'A', "^ads-", NULL, 0},
	{'A', "^adservice.", NULL, 0},
	{'A', "^affiliate.", NULL, 0},
	{'A', "^affiliates.", NULL, 0},
	{'A', "^banner", NULL, 0},
	{'A', "banner.", NULL, 0},
	{'A', "^banners", NULL, 0},
	{'A', "banners.", NULL, 0},
	{'A', "click.", NULL, 0},
	{'A', "^click-", NULL, 0},
	{'A', "clicks.", NULL, 0},
	{'A', "^clicks-", NULL, 0},
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
	
	// phishing
	{'P', "^paypal.com.", NULL, 0},
	{'P', "^paypal.co.uk.", NULL, 0},
	{'P', "^paypal.co.de.", NULL, 0},
	{'P', "^amazon.com.", NULL, 0},
	{'P', "^amazon.de.", NULL, 0},
	{'P', "^appleid.apple.com.", NULL, 0},
	{'P', "^https.secure.", NULL, 0},
	{'P', "^online.paypal.com.", NULL, 0},
	{'P', "^paypal-", NULL, 0},
	{'P', "^amazon", NULL, 0},
	{'P', "^google-", NULL, 0},
	{'P', "^appleid-", NULL, 0},
	{'P', "^icloud-", NULL, 0},
	{'P', "^iphone-", NULL, 0},
	{'P', "^itunes-", NULL, 0},

	{'M', "^xinchao", NULL, 0}, // about 2800 miners here!
	{0, NULL, NULL, 0}	// last entry
};

typedef struct hash_entry_t {
	struct hash_entry_t *next;
	char label;
	unsigned short hash2;
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
static inline int hash(const char *str, unsigned short *hash2) {
	uint32_t hash = 5381;
	int c;

	while ((c = *str++) != '\0')
		hash = ((hash << 5) + hash) ^ c; // hash * 33 ^ c

	*hash2 = hash % 39119;
	return (int) (hash & (MAX_HASH_ARRAY - 1));
}

void filter_add(char label, const char *domain) {
	assert(domain);
	if (strlen(domain) < 4) {
		fprintf(stderr, "Warning: not installing \"%s\" as a %s filter. This could be a full top domain.\n", domain, label2str(label));
		return;
	}

	HashEntry *h = malloc(sizeof(HashEntry));
	if (!h)
		errExit("malloc");
	h->label = label;
	h->name = strdup(domain);
	if (!h->name)
		errExit("strdup");

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
	filter_load_list('P', PATH_ETC_PHISHING_LIST, arg_clean_filters);
	filter_load_list('T', PATH_ETC_TRACKERS_LIST, arg_clean_filters);
	filter_load_list('F', PATH_ETC_FP_TRACKERS_LIST, arg_clean_filters);
	filter_load_list('M', PATH_ETC_COINBLOCKER_LIST, arg_clean_filters);
	filter_load_list('A', PATH_ETC_ADBLOCKER_LIST, arg_clean_filters);
	filter_load_list('H', PATH_ETC_HOSTS_LIST, arg_clean_filters);

#ifdef DEBUG_STATS
	int max_cnt = 0;
	int i;
	for (i = 0; i < MAX_HASH_ARRAY; i++) {
		int cnt = 0;
		HashEntry *ptr = blist[i];
		while (ptr) {
			cnt++;
			ptr = ptr->next;
		}

		if (cnt > max_cnt)
			max_cnt = cnt;
	}

	printf("*** %u filter entries, total memory %u\n", stats_entries, stats_mem);
	printf("*** longest filter htable line %d ***\n", max_cnt);
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
static inline char *silverpop(const char *str) {
	char *rv = "T";
	if (strncmp(str, "mkt", 3))
		return NULL;
	const char *ptr = str + 3;
	while (isdigit(*ptr))
		ptr++;
	if(strcmp(ptr, ".com") == 0)
		return rv;
	return NULL;
}

// 025gmail.com
// 000006138.com
static inline char *numbersdot(const char *str) {
	if (!isdigit(*str))
		return NULL;
	const char *ptr = str;
	while (isdigit(*ptr) || *ptr == '-')
		ptr++;
	if (strcmp(ptr, "gmail.com") == 0)
		return "A";
	else if (*ptr == '.') {
		ptr++;
		if (strchr(ptr, '.'))
			return NULL;
		return "A";
	}
	return NULL;
}

static char *custom_checks(const char *str) {
	char *rv = silverpop(str);
	if (rv)
		return rv;
	rv = numbersdot(str);
	if (rv)
		return rv;
	

	return NULL;
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

	// custom checks
	char *rv = custom_checks(str);
	if (rv) {
		if (verbose)
			printf("URL %s dropped by a custom rule\n", str);
		return rv;
	}
	
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
	stats_time += timetrace_end();
	stats_cnt++;
	if (stats_cnt >= 10) {
		printf("\n*** average filter access %.03f ms\n\n", stats_time / stats_cnt);
		fflush(0);
		stats_time = 0;
		stats_cnt = 0;
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

#ifdef HAVE_GCOV
		__gcov_flush();
#endif
	}
}

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
	".a88045584548111e997c60ac8a4ec150-1610510072.",
		//a88045584548111e997c60ac8a4ec150-1610510072.eu-central-1.elb.amazonaws.com
	".afc4d9aa2a91d11e997c60ac8a4ec150-2082092489.",
		//afc4d9aa2a91d11e997c60ac8a4ec150-2082092489.eu-central-1.elb.amazonaws.com
	".a5e652663674a11e997c60ac8a4ec150-1684524385.",
	".a351fec2c318c11ea9b9b0a0ae18fb0b-1529426863.",
	".affex.",		//affex.org
	".intentmedia.",	//partner.intentmedia.net
	".webtrekk.",	//webtrekk.net
	".wt-eu02.",		//wt-eu02.net
	".oghub.",		//oghub.io

	"tracking.bp01.net",
	"trck.a8.net",
	"mm.actionlink.jp",
	"cname.ebis.ne.jp",
	"0i0i0i0.com",
	"actonservice.com",
	"actonsoftware.com",
	"thirdparty.bnc.lt",
	"ddns.dataunlocker.com",
	"starman.fathomdns.com",
	"ad-cloud.jp",
	"hs.eloqua.com",
	"custom.plausible.io",
	"go.pardot.com",
	"ghochv3eng.trafficmanager.net",

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
