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

static int callback(const void *p1, const void *p2) {
	char *str1 =  *((char **) p1);
	char *str2 =  *((char **) p2);
//printf("%s %s\n", str1, str2);

	int len1 = strlen(str1);
	if (len1 == 0)
		return -1;
	int len2 = strlen(str2);
	if (len2 == 0)
		return 1;
	int min = (len1 < len2) ? len1 : len2;

	char *ptr1 = str1 + len1 - 1;
	char *ptr2 = str2 + len2 - 1;

	int i;
	for (i = 0; i <  min; i++, ptr1--, ptr2--) {
		if (*ptr1 == *ptr2)
			continue;
		if (*ptr1 < *ptr2)
			return -1;
		return 1;
	}

	if (len1 == len2)
		return 0;
	else if (len1 > len2)
		return 1;
	return -1;
}

static char *line_filter(char *buf) {
	if (*buf == '#')
		return NULL;
	if (*buf == '*') // handle dnstwist.it *original line
		return NULL;
	if (strncmp(buf, "fuzzer,domain,", 14) == 0) // handle dnstwist.it first line
		return NULL;
	char *ptr = strchr(buf, '\n');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(buf, '#');
	if (ptr)
		*ptr = '\0';

	// clean line start
	char *start = buf;
	while (*start == ' ' || *start == '\t')
		start++;

	if (*start == '\0')
		return NULL;

//printf("%d: start %s\n", __LINE__, start);
	// alienvolt, phishtank etc.
	ptr = strstr(start, "http");
	if (ptr) {
		ptr += 4;
		if (*ptr == 's')
			ptr++;
		if (strncmp(ptr, "://", 3) == 0)
			ptr += 3;
		else
			goto getout;
		start = ptr;
	}
	getout:

//printf("%d: start %s\n", __LINE__, start);
	if (strncmp(start, "127.0.0.1", 9) == 0 || strncmp(start, "0.0.0.0", 7) == 0) {
		while (*start != ' ' && *start != '\t' && *start != '\0')
			start++;
		if (*start == '\0')
			goto errout;
		while ((*start == ' ' || *start == '\t') && *start != '\0')
			start++;
		if (*start == '\0')
			goto errout;
	}
	if (*start == '\0')
		return NULL;

	// clean port numbers
	ptr = strchr(start, ':');
	if (ptr)
		*ptr = '\0';

	// clean line end
	ptr = strchr(start, ',');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, '#');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, '+');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, '=');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, '%');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, '/');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, '?');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, '"');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, ' ');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, ';');
	if (ptr)
		*ptr = '\0';
	ptr = strchr(start, '\t');
	if (ptr)
		*ptr = '\0';

	// remove an ending dot
	int len = strlen(start);
	if (*(start + len - 1) == '.')
		*(start + len - 1) = '\0';

	return start;
errout:
	fprintf(stderr, "Error: %s\n",  buf);
	exit(1);
}


char **line_in = NULL; //malloc(sizeof(char *) * (cnt + 1));
int line_in_cnt = 0;
int line_in_size = 0;
#define LINE_CHUNK 4096

void rsort_load(const char *fname) {
//	int cnt_start = line_in_cnt;
	if (is_dir(fname))
		return;
	printf("# loading %s", fname);
	fflush(0);

	// read file
	char *storage = read_file_malloc(fname);
	if (!storage) {
		fprintf(stderr, "Error: cannot read %s file\n", fname);
		exit(1);
	}

	// check dnstwist.it
	int dnstwist_it = 0;
	if (strncmp(storage, "fuzzer,domain,dns_a,", 20) == 0)
		dnstwist_it = 1;

	int domains = 0;
	char *ptr;
	while ((ptr = strsep(&storage, "\n")) != NULL) {
		if ((line_in_cnt + 10) >= line_in_size) {
			line_in = realloc(line_in, sizeof(char *) * (line_in_cnt + LINE_CHUNK));
			line_in_size += LINE_CHUNK;
		}

		if (dnstwist_it) {
			char *ptr1 = strchr(ptr, ',');
			if (!ptr1)
				goto errout;
			line_in[line_in_cnt] = ptr1 + 1;
		}
		else
			line_in[line_in_cnt] = ptr;

		char *start = line_filter(line_in[line_in_cnt]);
		if (start) {
			line_in[line_in_cnt++] = start;
			domains++;
		}
		else
			line_in[line_in_cnt] = NULL;
	}

	line_in[line_in_cnt] = NULL; // we allocated 10 more above!
	printf(" (%d)\n", domains);
	return;

errout:
	fprintf(stderr, "Error: file %s, %s\n", fname, ptr);
	exit(1);
}

char **rsort(void) {
	// sorting
	qsort(&line_in[0], line_in_cnt, sizeof(char *), callback);
	return line_in;
}

