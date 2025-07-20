/*
 * Copyright (C) 2019-2024 FDNS Authors
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

#include "dnsc.h"

#define MAXHASH 256
static Node *hlist[MAXHASH] = {NULL};

static void dedup_add(const char *name) {
	assert(name);

	Node *ptr = malloc(sizeof(Node));
	if (!ptr)
		errExit("malloc");
	memset(ptr, 0, sizeof(Node));
	ptr->name = strdup(name);
	if (!ptr->name)
		errExit("strdup");

	unsigned hval = hash(name, MAXHASH);
	ptr->next = hlist[hval];
	hlist[hval] = ptr;
}

// ret 1 if found
int dedup_search(const char *name) {
	Node *hptr = hlist[hash(name, MAXHASH)];
	while (hptr) {
		if (strcmp(hptr->name, name) == 0)
			return 1;
		hptr = hptr->next;
	}

	return 0;
}

#define MAXBUF 1024
void dedup_init(const char *fname) {
	assert(fname);

	FILE *fp = fopen(fname, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot open %s\n", fname);
		exit(1);
	}

	char buf[MAXBUF];
	int n = 0;
	while (fgets(buf, MAXBUF, fp)) {
		n++;
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		ptr = buf;
		if (*ptr == '\0')
			continue;

		while (*ptr == ' ' || *ptr == '\t')
			ptr++;
		if (*ptr == '#')
			continue;

		// 127.0.0.1 domain.com
		ptr = strchr(ptr, ' ');
		if (ptr == NULL || *(ptr + 1) == '\0') {
			fprintf(stderr, "Error: invalid line %d in %s file\n", n, fname);
			exit(1);
		}
		ptr++;
		if (strchr(ptr, ' ') || strchr(ptr, '\t')) {
			fprintf(stderr, "Error: invalid line %d in %s file\n", n, fname);
			exit(1);
		}
		dedup_add(ptr);
	}
}


