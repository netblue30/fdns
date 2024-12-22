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

#define HMAX 1024
typedef struct hnode_t {
	struct hnode_t *next;
	const char *name;
	int cnt;
} HNode;

HNode *ht[HMAX] = {NULL};

static void whitelist_add(const char *name) {
	HNode *hnode = malloc(sizeof(HNode));
	if (!hnode)
		errExit("malloc");
	memset(hnode, 0, sizeof(HNode));

	hnode->name = strdup(name);
	if (!hnode->name)
		errExit("strdup");

	unsigned h = hash(name, HMAX);
	hnode->next = ht[h];
	ht[h] = hnode;
}

void *whitelist_find(const char *name) {
	unsigned h = hash(name, HMAX);
	HNode *hnode = ht[h];

	while (hnode) {
		if (strcmp(hnode->name, name) == 0) {
			hnode->cnt++;
			return hnode;
		}
		hnode = hnode->next;
	}

	return NULL;
}

void whitelist_load(void) {
	char *fname = SYSCONFDIR "/whitelist";
	if (arg_debug)
		fprintf(stderr, "Loading domain whitelist from %s\n", fname);

	FILE *fp = fopen(fname, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot open whitelist file\n");
		exit(1);
	}

	char buf[LINE_MAX];
	while (fgets(buf, LINE_MAX, fp)) {
		if (*buf == '#')
			continue;
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		if (*buf == '\0')
			continue;

		char *start = buf;
		if (strncmp(buf, "127.0.0.1 ", 10) == 0)
			start += 10;
		else if (strncmp(buf, "0.0.0.0 ", 8) == 0)
			start += 8;

		whitelist_add(start);
	}
	fclose(fp);
}

void whitelist_print(int total_domains) {
	printf("# Whitelisted domains:\n");
	int i;
	for (i = 0; i < HMAX; i++) {
		HNode *hnode = ht[i];
		while (hnode) {
			if (hnode->cnt)
				printf("# %6d (%.02f%%) %s\n",
					hnode->cnt,
					((double) hnode->cnt / (double) total_domains) * 100,
					hnode->name);
			hnode = hnode->next;
		}
	}
}
