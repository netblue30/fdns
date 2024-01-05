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

#ifndef DNSC_H
#define DNSC_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>

#define errExit(msg)    do { char msgout[500]; sprintf(msgout, "Error %s:%s(%d)", msg, __FUNCTION__, __LINE__); perror(msgout); exit(1);} while (0)

// memory printout
static inline void dbg_memory(void *ptr, ssize_t len, const char *name) {
	if (name)
		printf("%s:\n", name);

	const uint8_t *ptr2 = (uint8_t *) ptr;
	ssize_t i;
	for ( i = 0; i < len; i++) {
		if (i % 16 == 0)
			printf("%04lx: ", i);
		if ((i + 8) % 16 == 0)
			printf("- ");
		printf("%02x ", ptr2[i]);
		if (i % 16 == 15)
			printf("\n");
	}
	printf("\n");
}

// djb2 hash function by Dan Bernstein
static inline unsigned hash(const char *str, unsigned array_cnt) {
	unsigned hash = 5381;
	int c;

	while ((c = *str++) != '\0')
		hash = ((hash << 5) + hash) ^ c; // hash * 33 ^ c

	return (hash & (array_cnt - 1));
}

// read a text file; \0 is added at the end of the text
static inline char *read_file_malloc(const char *fname) {
	assert(fname);

	int fd = open(fname, O_RDONLY);
	if (fd == -1)
		return NULL;
	off_t len = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	char *rv = malloc(len + 1);	// add a \0 at the end of the string
	if (!rv)
		errExit("malloc");
	memset(rv, 0, len);

	ssize_t cnt = 0;
	char *ptr = rv;
	while (cnt != len) {
		ssize_t cnt2 = read(fd, ptr + cnt, len - cnt);
		if (cnt2 == -1) {
			close(fd);
			return NULL;
		}
		cnt += cnt2;
		ptr += cnt2;
	}
	rv[cnt] = '\0';
//printf("#%s#\n", rv);
	close(fd);
	return rv;
}


#include <sys/stat.h>
static inline int is_dir(const char *fname) {
	assert(fname);
	if (*fname == '\0')
		return 0;

	// if fname doesn't end in '/', add one
	struct stat s;
	if (stat(fname, &s) == 0) {
		if (S_ISDIR(s.st_mode))
			return 1;
	}

	return 0;
}

// main.c
extern int arg_short;
extern int arg_debug;
typedef struct node_t {
	struct node_t *next;
	char *name;
	int len;	// len of name string
	int cnt;	// number of occurrences

	// subdomain filtering
	int scnt;
	char *s1;
	char *s2;
	char *s3;
	char *s4;
} Node;
extern Node *domains;
int get_limit(void);
extern char execpath[LINE_MAX+ 1];

// rsort.c
void rsort_load(const char *fname);
char **rsort(void);

// subs.c
extern int tld_cnt;
void subs_print(int total_domains);

// whitelist.c
void *whitelist_find(const char *name);
void whitelist_load(void);
void whitelist_print(int total_domains);

// tld.c
char *tld_find(const char *name);

// tech.c
void tech_check(const char *name);
void tech_print(int total_domains);

// tld_top.c
void tld_top_print(int total_domains);

#endif
