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
#include "fdns.h"

typedef struct wentry_t {
	struct wentry_t *next;
	const char *domain;
} WEntry;

static WEntry *wlist = NULL;

int whitelist_active(void) {
	if (wlist)
		return 1;
	return 0;
}

// count entries
int whitelist_cnt(void) {
	int cnt = 0;
	WEntry *w = wlist;
	while (w) {
		cnt++;
		w = w->next;
	}

	return cnt;
}

// add new entry
void whitelist_add(const char *domain) {
	assert(domain);

	// skip www.
	const char *dm = domain;
	if (strncmp(domain, "www.", 4) == 0)
		dm = domain + 4;



	// in list already?
	WEntry *w = wlist;
	while (w != NULL) {
		if (strcmp(dm, w->domain) == 0)
			return;
		w = w->next;
	}

	WEntry *wnew = malloc(sizeof(WEntry));
	if (!wnew)
		errExit("malloc");
	wnew->domain = strdup(dm);
	if (!wnew->domain)
		errExit("strdup");
	wnew->next = wlist;
	wlist = wnew;
	if (arg_id == 0) {
		printf("whitelist %s\n", wnew->domain);
		fflush(0);
	}
}

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
	WEntry *w = wlist;
	while (w) {
		if (asprintf(&argv[i], "--whitelist=%s", w->domain) == -1)
			errExit("asprintf");
		w = w->next;
		i++;
	}
}

// 1 not found, 0 found
int whitelist_blocked(const char *domain) {
	assert(domain);

	// skip www.
	const char *dm = domain;
	if (strncmp(domain, "www.", 4) == 0)
		dm = domain + 4;

	int i = 0;
	WEntry *w = wlist;
	while (w) {
		if (strcmp(w->domain, dm) == 0)
			return 0;
		w = w->next;
	}

	return 1;
}