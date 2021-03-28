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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAXBUF (10 * 1024)
static char outbuf[MAXBUF];
int chunk_size = 100;

static char *run_program(const char *cmd) {
	assert(cmd);
	FILE *fp = popen(cmd, "r");
	if (!fp) {
		perror("popen");
		exit(1);
	}

	int len = 0;
	while (len < MAXBUF && fgets(outbuf + len, MAXBUF - len, fp)) {
		len += strlen(outbuf + len);
	}
	pclose(fp);
	return outbuf;
}

// supported formats:
//    - lines in regular hosts files with ip addresses of 127.0.0.1 and 0.0.0.0
//    - lists of domain names, one domain per line
static void test(FILE *fpin, FILE *fpout) {
	assert(fpin);
	assert(fpout);

	char buf[MAXBUF];
	int i = 0;
	int j = 0;
	while (fgets(buf, MAXBUF, fpin)) {
		i++;
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		// comments
		char *start = ptr;
		if (*start == '#' || *start == '\0') { // preserve comments, blank lines
			fprintf(fpout, "%s\n", start);
			continue;
		}
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

		// run the domain through nslookup
		char *cmd;
		if (asprintf(&cmd, "nslookup %s 1.1.1.1", start) == -1) {
			perror("asprintf");
			exit(1);
		}

		char *output = run_program(cmd);
		assert(output);
		if (strstr(output, "NXDOMAIN") == NULL) {
			j++;
			printf("*");
			fflush(0);
			fprintf(fpout, "127.0.0.1 %s\n", start);
			fflush(0);
		}
		free(cmd);
	}
	printf("*** %d removed ***", i - j);
	fflush(0);
}

static int split(const char *fname_in, const char *fname_out) {
	assert(fname_in);
	assert(fname_out);
	FILE *fp = fopen(fname_in, "r");
	if (!fp) {
		perror("fopen in");
		exit(1);
	}

	FILE *fpout = NULL;


	char buf[MAXBUF];
	int line = 0;
	int chunk = 0;
	while (fgets(buf, MAXBUF, fp)) {
		if ((line % chunk_size) == 0) {
			if (fpout)
				fclose(fpout);
			char *f;
			if (asprintf(&f, "%s-%d", fname_out, chunk) == -1) {
				perror("asprintf");
				exit(1);
			}
			fpout = fopen(f, "w");
			if (!fpout) {
				perror("fopen out");
				exit(1);
			}
			free(f);
			chunk++;
		}
		line++;

		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		// comments
		char *start = ptr;
		if (*start == '#' || *start == '\0') { // preserve comments, blank lines
			fprintf(fpout, "%s\n", start);
			continue;
		}
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
		 fprintf(fpout, "127.0.0.1 %s\n", start);
	}

	fclose(fp);
	fclose(fpout);
	return chunk;
}

static void usage(void) {
	printf("nxdomain - simple utility to remove domains from a list based on NXDOMAIN reported by nslookup\n");
	printf("Usage: nxdomain file_in file_out\n");
}

static void run_chunk(int chunk, int chunks) {
	printf("*** chunk %d/%d ***", chunk, chunks);
	fflush(0);

	char *fin;
	if (asprintf(&fin, "temp-%d", chunk) == -1) {
		perror("asprintf");
		exit(1);
	}
	FILE *fpin = fopen(fin, "r");
	if (!fpin) {
		perror("fopen");
		exit(1);
	}

	char *fout;
	if (asprintf(&fout, "tempout-%d", chunk) == -1) {
		perror("asprintf");
		exit(1);
	}
	FILE *fpout = fopen(fout, "w");
	if (!fpout) {
		perror("fopen out");
		exit(1);
	}

	test(fpin, fpout);
	fclose(fpin);
	fclose(fpout);
	int rv = unlink(fin);
	(void) rv;
	free(fin);
	free(fout);
}


int main(int argc, char **argv) {
	if (argc != 3) {
		usage();
		return 1;
	}
	if (strcmp(argv[1], "-h") == 0) {
		usage();
		return 0;
	}

	int chunks = split(argv[1], "temp");
	fflush(0);
	int i;
	for (i = 0; i < chunks; i += 3) {
		pid_t child = fork();
		if (child == -1) {
			perror("fork");
			exit(1);
		}
		if (child == 0) {
			child = fork();
			if (child == -1) {
				perror("fork");
				exit(1);
			}
			if (child == 0) {
				run_chunk(i, chunks);
				exit(0);
			}
			else if ((i + 1) < chunks)
				run_chunk(i + 1, chunks);
			int wstatus;
			waitpid(child, &wstatus, 0);
			exit(0);
		}
		else if ((i + 2) < chunks)
			run_chunk(i + 2, chunks);

		int wstatus;
		waitpid(child, &wstatus, 0);
	}

	int rv = unlink(argv[2]);
	(void) rv;
	for (i = 0; i < chunks; i++) {
		char *cmd;
		if (asprintf(&cmd, "cat tempout-%d >> %s", i, argv[2]) == -1) {
			perror("asprintf");
			exit(1);
		}
		rv = system(cmd);
		free(cmd);
	}

	rv = system("rm tempout-*");
	(void) rv;
	printf("\n");

	return 0;
}
