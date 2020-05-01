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

/*
Simple tool to extract the server list for wordpress site

<li><a href="https://www.cira.ca/cybersecurity-services/canadianshield/how-works">cira-family</a> (family, Canada)<br />
family.canadianshield.cira.ca/dns-query (149.112.121.30)</li>
<li><a href="https://www.cira.ca/cybersecurity-services/canadianshield/how-works">cira-family2</a> (family, Canada)<br />
family.canadianshield.cira.ca/dns-query (149.112.122.30)</li>

<li><a href="https://blahdns.com">blahdns-jp</a> (Japan, adblocker)<br />
doh-jp.blahdns.com/dns-query (45.32.55.94)</li>

<li><a href="https://blahdns.com">blahdns-de</a> (Germany, adblocker)<br />
doh-de.blahdns.com/dns-query (159.69.198.101)</li>
<li><a href="https://blahdns.com">blahdns-fi</a> (Finland, adblocker)<br />
doh-fi.blahdns.com/dns-query (95.216.212.177)</li>

Remove Luxembourg from nixnet Americas

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#define errExit(msg)    do { char msgout[500]; snprintf(msgout, 500, "Error %s: %s:%d %s", msg, __FILE__, __LINE__, __FUNCTION__); perror(msgout); exit(1);} while (0)
// check ip:port
// return -1 if error
static inline int check_addr_port(const char *str) {
	unsigned a, b, c, d, e;

	// extract ip
	int rv = sscanf(str, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &e);
	if (rv != 5 || a > 255 || b > 255 || c > 255 || d > 255 || e > 0xffffffff)
		return -1;
	return 0;
}

typedef struct dnsserver_t {
	struct dnsserver_t *next;// linked list
	int  active;		// flag for random purposes

	// server data
	char *name;	// name
	char *website;	// website
	char *zone;		// geographical zone
	char *tags;	// description
	char *address;	// IP address
	char *host;		// POST request first line
	char *request;	// full POST request
	int sni;		// 1 or 0
	int keepalive;	// keepalive in seconds
} DnsServer;
static DnsServer *slist_americas = NULL;
static DnsServer *slist_asiapac = NULL;
static DnsServer *slist_europe = NULL;
static DnsServer *slist_anycast = NULL;

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
	int found = 0;
	while (fgets(buf, 4096, fp)) {
		(*linecnt)++;

		// comments
		if (*buf == '#')
			continue;

		// remove \n
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';

		if (strncmp(buf, "name: ", 6) == 0) {
			if (s->name)
				goto errout;
			s->name = strdup(buf + 6);
			if (!s->name)
				errExit("strdup");
			found = 1;
		}
		else if (strncmp(buf, "website: ", 9) == 0) {
			if (s->website)
				goto errout;
			s->website = strdup(buf + 9);
			if (!s->website)
				errExit("strdup");
			found = 1;
		}
		else if (strncmp(buf, "zone: ", 6) == 0) {
			if (s->zone)
				goto errout;
			s->zone = strdup(buf + 6);
			if (!s->zone)
				errExit("strdup");
			found = 1;
		}
		else if (strncmp(buf, "tags: ", 6) == 0) {
			if (s->tags)
				goto errout;
			s->tags = strdup(buf + 6);
			if (!s->tags)
				errExit("strdup");
			found = 1;
		}
		else if (strncmp(buf, "address: ", 9) == 0) {
			if (s->address)
				goto errout;
			s->address = strdup(buf + 9);
			if (!s->address)
				errExit("strdup");

// todo: accept a server name in parallel with IP addresses
			// check address:port
			if (check_addr_port(s->address)) {
				fprintf(stderr, "Error: file %s, line %d, invalid address:port\n", fname, *linecnt);
				exit(1);
			}
			found = 1;
		}
		else if (strncmp(buf, "host: ", 6) == 0) {
			if (s->host)
				goto errout;
			s->host = strdup(buf + 6);
			if (!s->host)
				errExit("strdup");
			found = 1;
		}
		else if (strncmp(buf, "sni: ", 5) == 0) {
			if (s->sni)
				goto errout;
			if (strcmp(buf + 5, "yes") == 0)
				s->sni = 1;
			else if (strcmp(buf + 5, "no") == 0)
				s->sni = 0;
			else {
				fprintf(stderr, "Error: file %s, line %d, wrong SNI setting\n", fname, *linecnt);
				exit(1);
			}
		}
		else if (strncmp(buf, "keepalive: ", 11) == 0) {
			if (s->keepalive)
				goto errout;
			if (sscanf(buf + 11, "%d", &s->keepalive) != 1 || s->keepalive <= 0) {
				fprintf(stderr, "Error: file %s, line %d, invalid keepalive\n", fname, *linecnt);
				exit(1);
			}

			// check server data
			if (!s->name || !s->website || !s->zone || !s->tags || !s->address || !s->host) {
				fprintf(stderr, "Error: file %s, line %d, one of the server fields is missing\n", fname, *linecnt);
				exit(1);
			}

			return s;
		}
	}

	if (found) {
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

DnsServer *duplicate(DnsServer *s) {
	assert(s);
	DnsServer *snew = malloc(sizeof(DnsServer));
	if (!snew)
		errExit("malloc");
	memcpy(snew, s, sizeof(DnsServer));
	snew->next = NULL;
	return snew;
}

static void load_list(void) {
	// load all server entries from /etc/fdns/servers in list
	FILE *fp = fopen("../../etc/servers", "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot find server file\n");
		exit(1);
	}

	int linecnt = 0; // line counter
	DnsServer **ptr_americas = &slist_americas;
	DnsServer **ptr_asiapac = &slist_asiapac;
	DnsServer **ptr_europe = &slist_europe;
	DnsServer **ptr_anycast = &slist_anycast;
	int cnt = 0;
	while (1) {
		DnsServer *s = read_one_server(fp, &linecnt, "../../etc/servers");
		if (!s)
			break;

		// push it to the end of the list
		if (strstr(s->tags, "anycast")) {
			*ptr_anycast = s;
			ptr_anycast = &s->next;
		}
		else {
			int added = 0;
			if (strstr(s->tags, "Americas") && !strstr(s->tags, "anycast")) {
				*ptr_americas = s;
				ptr_americas = &s->next;
				cnt++;
				added = 1;
			}
			if (strstr(s->tags, "Asia-Pacific") && !strstr(s->tags, "anycast")) {
				if (added) {
					s = duplicate(s);
				}

				*ptr_asiapac = s;
				ptr_asiapac = &s->next;
				cnt++;
				added = 1;
			}
			if (strstr(s->tags, "Europe") && !strstr(s->tags, "anycast")) {
				if (added) {
					s = duplicate(s);
				}
				*ptr_europe = s;
				ptr_europe = &s->next;
				cnt++;
				added = 1;
			}
		}
	}

	printf("total %d\n", cnt);
	fclose(fp);
}


char *clean_tags(char *tag) {
	assert(tag);
	char *rv = malloc(strlen(tag) + 1);
	if (!rv)
		errExit("malloc");
	char *rvptr = rv;
	*rvptr = '\0';
	char *start = tag;
	char *ptr = tag;
	while (*ptr) {
		int skip = 0;
		if (strncmp(ptr, "Americas", 8) == 0 ||
		    strncmp(ptr, "America-East",  12) == 0 ||
		    strncmp(ptr, "America-West", 12) == 0 ||
		    strncmp(ptr, "Asia-Pacific", 12) == 0 ||
		    strncmp(ptr, "Europe", 6) == 0)
			skip = 1;

		if (skip) {
			while(*ptr != '\0' && *ptr != ',' && *ptr != ' ')
				ptr++;
			while (*ptr != '\0' && (*ptr == ',' || *ptr == ' '))
				ptr++;
		}
		else {
			// copy
			while(*ptr != '\0' && *ptr != ',' && *ptr != ' ')
				*rvptr++ = *ptr++;
			while (*ptr != '\0' && (*ptr == ',' || *ptr == ' '))
				*rvptr++ = *ptr++;
		}
	}
//	free(start); // danger - duplicating server structures below!!!
	*rvptr = '\0';

	int len = strlen(rv);
	if (len > 2) {
		ptr = rv + len - 2;
		if (*ptr == ',')
			*ptr = '\0';
	}

	return rv;

}

void print_server(DnsServer *ptr) {
	assert(ptr);

	ptr->tags = clean_tags(ptr->tags);
	char *c = strchr(ptr->address, ':');
	if (c)
		*c = '\0';
	printf("<li><a href=\"%s\">%s</a> ", ptr->website, ptr->name);
	if (*ptr->tags)
		printf("(%s)", ptr->tags);
	printf("<br />\n");
	printf("%s (%s)</li>\n", ptr->host, ptr->address);
}

void print_list(void) {
	printf("\n\n*** Anycast ***\n");
	DnsServer *ptr = slist_anycast;
	while (ptr) {
		print_server(ptr);
		ptr = ptr->next;
	}

	printf("\n\n*** Americas ***\n");
	ptr = slist_americas;
	while (ptr) {
		print_server(ptr);
		ptr = ptr->next;
	}

	printf("\n\n*** Asia-Pacific ***\n");
	ptr = slist_asiapac;
	while (ptr) {
		print_server(ptr);
		ptr = ptr->next;
	}

	printf("\n\n*** Europe ***\n");
	ptr = slist_europe;
	while (ptr) {
		print_server(ptr);
		ptr = ptr->next;
	}
}

int main(void) {
	load_list();
	print_list();
	return 0;
}
