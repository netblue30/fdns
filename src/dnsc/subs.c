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

#include "dnsc.h"

#define MAX_REORDER 1024
static Node *subs_node[MAX_REORDER] = {NULL};
static int subs_index = 0;
int tld_cnt = 0;

static int callback(const void *n1, const void *n2) {
	Node **ptr1 = (Node **) n1;
	Node *node1 = *ptr1;
	Node **ptr2 = (Node **) n2;
	Node *node2 = *ptr2;

	return (node1->cnt < node2->cnt);
}

// return 1 if found
static int subs_find(const char *name) {
	if (subs_index == 0)
		return 0;

	int len = strlen(name);
	int i;
	for (i = 0; i < subs_index; i++) {
		int delta = len - subs_node[i]->len;
		if (delta == 0 && strcmp(name, subs_node[i]->name) == 0)
			return 1;

		if (delta > 0 && strcmp(name + delta, subs_node[i]->name) == 0) {
			if (name[delta - 1] == '.')
				return 1;
		}
//		if (strstr(name, subs_node[i]->name)) {
//			return 1;
//		}
	}

	return 0;
}


static void subs_add(char *name, int cnt) {
	if (subs_find(name))
		return;

	Node *n = malloc(sizeof(Node));
	if (!n)
		errExit("malloc");
	memset(n, 0, sizeof(Node));
	n->name = name;
	n->cnt = cnt;
	n->len = strlen(name);
	subs_node[subs_index++] = n;
}

static void extract_subs1(int limit) {
	if (!domains)
		return;
	Node *ptr = domains;
	while (ptr && ptr->s1 == NULL)
		ptr = ptr->next;
	if (ptr == NULL)
		return;
	char *search = ptr->s1;
	void *w = whitelist_find(search);
	char *name = ptr->name;
	int cnt = 0;
	while (ptr) {
		if (ptr->s1) {
			if (strcmp(search, ptr->s1) == 0)
				cnt += ptr->cnt;
			else {
				if (!w && cnt > limit && strcmp(search, name) != 0 &&
				    tld_find(search)) {
					subs_add(search, cnt);
					tld_cnt += cnt;
				}
				cnt = ptr->cnt;
				search = ptr->s1;
				w = whitelist_find(search);
				name = ptr->name;
			}
		}
		ptr = ptr->next;
	}

	if (!w && cnt > limit && tld_find(search)) {
		subs_add(search, cnt);
		tld_cnt += cnt;
	}
}

static void extract_subs2(int limit) {
	if (!domains)
		return;
	Node *ptr = domains;
	while (ptr && ptr->s2 == NULL)
		ptr = ptr->next;
	if (ptr == NULL)
		return;
	char *search = ptr->s2;
	void *w = whitelist_find(search);
	int cnt = 0;
	while (ptr) {
		if (ptr->s2) {
			if (strcmp(search, ptr->s2) == 0)
				cnt += ptr->cnt;
			else {
				if (!w && cnt > limit)
					subs_add(search, cnt);
				cnt = ptr->cnt;
				search = ptr->s2;
				w = whitelist_find(search);
			}
		}
		ptr = ptr->next;
	}

	if (!w && cnt > limit)
		subs_add(search, cnt);
}

static void extract_subs3(int limit) {
	if (!domains)
		return;
	Node *ptr = domains;
	while (ptr && ptr->s3 == NULL)
		ptr = ptr->next;

	if (ptr == NULL)
		return;
	char *search = ptr->s3;
	void *w = whitelist_find(search);
	int cnt = 0;
	while (ptr) {
		if (ptr->s3) {
			if (strcmp(search, ptr->s3) == 0)
				cnt += ptr->cnt;
			else {
				if (!w && cnt > limit)
					subs_add(search, cnt);
				cnt = ptr->cnt;
				search = ptr->s3;
				w = whitelist_find(search);
			}
		}
		ptr = ptr->next;
	}

	if (!w && cnt > limit)
		subs_add(search, cnt);
}

static void extract_subs4(int limit) {
	if (!domains)
		return;
	Node *ptr = domains;
	while (ptr && ptr->s4 == NULL)
		ptr = ptr->next;

	if (ptr == NULL)
		return;
	char *search = ptr->s4;
	void *w = whitelist_find(search);
	int cnt = 0;
	while (ptr) {
		if (ptr->s4) {
			if (strcmp(search, ptr->s4) == 0)
				cnt += ptr->cnt;
			else {
				if (!w && cnt > limit)
					subs_add(search, cnt);
				cnt = ptr->cnt;
				search = ptr->s4;
				w = whitelist_find(search);
			}
		}
		ptr = ptr->next;
	}

	if (!w && cnt > limit)
		subs_add(search, cnt);
}

void subs_print(int total_domains) {
	if (!domains)
		return;
	int limit = get_limit();
	extract_subs1(limit);
	extract_subs2(limit);
	extract_subs3(limit);
	extract_subs4(limit);
	if (subs_index == 0)
		return;
	qsort(subs_node, subs_index, sizeof(Node *), callback);

	// count subs
	int subs_total = 0;
	int i;
	for (i = 0; i < subs_index; i++)
		subs_total += subs_node[i]->cnt;

	// print subs
	printf("# Short list: heavily compressed list covering %.02f%% of the input\n", ((double) subs_total / (double) total_domains) * 100);
	for (i = 0; i < subs_index; i++) {
		if (arg_short) {
			if (strlen(subs_node[i]->name) < 30)
				printf("127.0.0.1 %-30s # %d (%.02f%%)\n", subs_node[i]->name, subs_node[i]->cnt, ((double) subs_node[i]->cnt / (double) total_domains) * 100);
			else
				printf("127.0.0.1 %s # %d (%.02f%%)\n", subs_node[i]->name, subs_node[i]->cnt, ((double) subs_node[i]->cnt / (double) total_domains) * 100);
		}
		else
			printf("#%02d:   %6d (%.02f%%) %s\n", i + 1, subs_node[i]->cnt, ((double) subs_node[i]->cnt / (double) total_domains) * 100, subs_node[i]->name);
	}

	// free mem
	for (i = 0; i < subs_index; i++)
		free(subs_node[i]);
}