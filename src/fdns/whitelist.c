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

// domain list
typedef struct dentry_t {
	struct dentry_t *next;
	size_t len; // strlen(domain)
	const char *domain;
} DEntry;

static DEntry *wlist = NULL; // whitelist

// is active?
int whitelist_active(void) {
	return (wlist)? 1: 0;
}


// count entries
int whitelist_cnt(void) {
	DEntry *dlist = wlist;
	int cnt = 0;
	while (dlist) {
		cnt++;
		dlist = dlist->next;
	}

	return cnt;
}

void whitelist_add(const char *domain) {
	assert(domain);
	DEntry **dlist = &wlist;
	assert(dlist);

	// skip www.
	const char *dm = domain;
	if (strncmp(domain, "www.", 4) == 0)
		dm = domain + 4;

	// in list already?
	DEntry *d = *dlist;
	while (d != NULL) {
		if (strcmp(dm, d->domain) == 0)
			return;
		d = d->next;
	}

	DEntry *dnew = malloc(sizeof(DEntry));
	if (!dnew)
		errExit("malloc");
	dnew->domain = strdup(dm);
	if (!dnew->domain)
		errExit("strdup");
	dnew->len = strlen(dnew->domain);
	dnew->next = *dlist;
	*dlist = dnew;

	if (arg_id == 0) {
		printf("whitelist %s\n", domain);
		fflush(0);
	}
}

// load file
void whitelist_load_file(const char *fname) {
	assert(fname);

	FILE *fp = fopen(fname, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot open %s\n", fname);
		fprintf(stderr, "If AppArmor is enabled, please place the file in %s directory\n", SYSCONFDIR);
		exit(1);
	}

	char buf[MAXBUF];
	while (fgets(buf, MAXBUF, fp)) {
		// cleanup
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;
		char *start = ptr;
		if (*ptr == '\0' || *ptr == '#') // empty line, comments
			continue;
		ptr = buf + strlen(buf) - 1;
		while (*ptr == ' ' || *ptr == '\t') {
			*ptr = '\0';
			ptr--;
		}

		whitelist_add(start);
	}

	fclose(fp);
}

// re-generate the command line
void whitelist_command(char **argv) {
	assert(argv);

	int i = 0;
	DEntry *d = wlist;
	while (d) {
		if (asprintf(&argv[i], "--whitelist=%s", d->domain) == -1)
			errExit("asprintf");
		d = d->next;
		i++;
	}
}

// 1 not found, 0 found
// full domain name matching
// Example: fdns --whitelist=gentoo.org --whitelist=security.gentoo.org
int whitelist_blocked(const char *domain) {
	assert(domain);

	// skip www.
	const char *dm = domain;
	if (strncmp(domain, "www.", 4) == 0)
		dm = domain + 4;

	DEntry *d = wlist;
	while (d) {
		if (strcmp(d->domain, dm) == 0)
			return 0;
		d = d->next;
	}

	return 1;
}
