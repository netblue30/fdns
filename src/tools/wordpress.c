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
*/

#include "../fdns/fdns.h"
// stub
int arg_disable_local_doh = 0;
void filter_add(char label, const char *domain) {(void) label; (void) domain;}

static DnsServer *slist_americas = NULL;
static DnsServer *slist_asiapac = NULL;
static DnsServer *slist_europe = NULL;
static DnsServer *slist_anycast = NULL;
static int arg_anycast = 0;
static int arg_americas = 0;
static int arg_asia_pacific = 0;
static int arg_europe = 0;

// returns NULL for end of list
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
			found = 1;
		}
		else if (strncmp(buf, "host: ", 6) == 0) {
			if (s->host)
				goto errout;
			s->host = strdup(buf + 6);
			if (!s->host)
				errExit("strdup");
			found = 1;


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
			if (s->keepalive_min)
				goto errout;
			if (sscanf(buf + 11, "%d", &s->keepalive_min) != 1 || s->keepalive_min <= 0) {
				fprintf(stderr, "Error: file %s, line %d, invalid keepalive\n", fname, *linecnt);
				exit(1);
			}
//			s->keepalive = 25;

			// check server data
			if (!s->name || !s->website || !s->zone || !s->tags || !s->address || !s->host) {
				fprintf(stderr, "Error: file %s, line %d, one of the server fields is missing\n", fname, *linecnt);
				exit(1);
			}

			// add host to filter
			if (arg_disable_local_doh)
				filter_add('D', s->host);


			// servers tagged as admin-down or firefox-only are not take into calculation
			if (strstr(s->tags, "admin-down")) {
				free(s);
				// go to next server in the list
				return read_one_server(fp, linecnt, fname);
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

		// push the server to the end of the list
		if (strstr(s->name, "cloudflare") ||
		    strstr(s->name, "nextdns") ||
		    strstr(s->name, "adguard") ||
		    strstr(s->name, "cleanbrowsing") ||
		    strstr(s->name, "quad9")) {
			*ptr_anycast = s;
			ptr_anycast = &s->next;
		}
		else {
			int added = 0;
			if (strstr(s->tags, "Americas")) {
				*ptr_americas = s;
				ptr_americas = &s->next;
				cnt++;
				added = 1;
			}
			if (strstr(s->tags, "Asia-Pacific")) {
				if (added) {
					s = duplicate(s);
				}

				*ptr_asiapac = s;
				ptr_asiapac = &s->next;
				cnt++;
				added = 1;
			}
			if (strstr(s->tags, "Europe")) {
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
		    strncmp(ptr, "Europe", 6) == 0 ||
		    strncmp(ptr, "firefox-only", 12) == 0)
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


void print_server(DnsServer *ptr, char *extra) {
	assert(ptr);

	ptr->tags = clean_tags(ptr->tags);
	char *c = strchr(ptr->address, ':');
	if (c)
		*c = '\0';
	printf("<li><a href=\"%s\">%s</a> ", ptr->website, ptr->name);
	int geocast = 0;
	if (*ptr->tags) {
		if (strstr(ptr->tags, "geocast")) {
			ptr->tags += 7;
			if (*ptr->tags == ',')
				ptr->tags++;
			if (*ptr->tags == ' ')
				ptr->tags++;
			geocast = 1;
		}

		printf("(");
		if (ptr)
			printf("%s", ptr->tags);
		if (extra)
			printf("%s", extra);
		printf(")");
	}

	printf("<br />\n");
	if (geocast)
		printf("%s%s (geocast)</li>\n", ptr->host, ptr->path);
	else
		printf("%s%s (%s)</li>\n", ptr->host, ptr->path, ptr->address);
}

void print_start(void) {
	printf("\n<table><tr>\n");
}
void print_end(void) {
	printf("</tr></table>\n\n\n");
}


// commons-host
//    Americas - 7 servers US+Canda
//    Asia-Pacific - 9 servers
//    Europe: - 5 servers Europe, 1 Middle-East
void print_list(void) {
	DnsServer *ptr;

	// anycast table
	if (arg_anycast) {
		printf("\n<table><tr><td><ul>\n");
		ptr = slist_anycast;
		while (ptr) {
			print_server(ptr, NULL);
			ptr = ptr->next;
		}
		printf("</ul></td></tr></table>\n\n\n");
	}

	// Americas
	if (arg_americas) {
		printf("<table><tr>\n");
		// Americas
		printf("<td><p style=\"text-align:center;\"><b>Americas</b></p><ul>\n");
		ptr = slist_americas;
		while (ptr) {
			char *extra = NULL;
			if (strcmp(ptr->name, "commons-host") == 0)
				extra = "7 servers US+Canada";
			print_server(ptr, extra);
			ptr = ptr->next;
		}
		printf("</ul>\n");
	}

	// Asia-Pacific
	if (arg_asia_pacific) {
		printf("<p style=\"text-align:center;\"><b>Asia-Pacific</b></p><ul>\n");
		ptr = slist_asiapac;
		while (ptr) {
			char *extra = NULL;
			if (strcmp(ptr->name, "commons-host") == 0)
				extra = "9 servers";
			print_server(ptr, extra);
			ptr = ptr->next;
		}
		printf("</ul>\n");
	}

	// Europe
	if (arg_europe) {
		printf("<p style=\"text-align:center;\"><b>Europe, Middle-East, Africa</b></p><ul>\n");
		ptr = slist_europe;
		int i = 0;
		while (ptr) {
			if (i == 5)
				printf("</ul></td><td><p style=\"text-align:center;\"><b>Europe, Middle-East, Africa (cont.)</b></p><ul>\n");
			char *extra = NULL;
			if (strcmp(ptr->name, "commons-host") == 0)
				extra = "5 servers Europe, 1 Middle-East";
			print_server(ptr, extra);
			ptr = ptr->next;
			i++;
		}
		printf("</ul>\n");
	}

	printf("</td></tr></table>\n\n\n");
}

void usage(void) {
	printf("Usage: wordpress options\n");
	printf("Options:\n");
	printf("    --anycast\n");
	printf("    --americas\n");
	printf("    --asia-pacific\n");
	printf("    --europe\n");
}
int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Error: invalid params\n");
		usage();
		return -1;
	}

	int i;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--anycast") == 0)
			arg_anycast = 1;
		else if (strcmp(argv[i], "--americas") == 0)
			arg_americas = 1;
		else if (strcmp(argv[i], "--asia-pacific") == 0)
			arg_asia_pacific = 1;
		else if (strcmp(argv[i], "--europe") == 0)
			arg_europe = 1;
	}

	load_list();
	print_list();
	return 0;
}
