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


//***************************************************************
// Supported file formats:
//    - regular hosts files with ip addresses of 127.0.0.1 or 0.0.0.0
//    - domain name lists, one domain per line
//***************************************************************


#include "nxdomain.h"
#include <sys/wait.h>

static char *arg_fin = NULL;
static char *arg_fout = NULL;

#define MAXBUF (10 * 1024)

static void test(FILE *fpin, FILE *fpout) {
	assert(fpin);
	assert(fpout);

	char buf[MAXBUF];
	int i = 0;
	int j = 0;
	char *start = "not runing";
	while (fgets(buf, MAXBUF, fpin)) {
		i++;
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		// comments
		start = ptr;
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


		if (strcspn(start, "\\&!?\"'<>%^(){}[];,|") != strlen(start)) {
			fprintf(stderr, "\nError: invalid domain %s, skipping...\n", start);
			continue;
		}

		// run the domain through nslookup
		usleep(200000);
		if (resolver(start) == 0) {
			j++;
			printf("*");
			fflush(0);
			fprintf(fpout, "%s\n", start);
			fflush(0);
		}
	}
	printf("### %d removed, last request %s ###", i - j, start);
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
		if ((line % FILE_CHUNK_SIZE) == 0) {
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

static void run_chunk(int chunk, int chunks, const char *tname_in, const char *tname_out) {
	fprintf(stderr, "\n### chunk %d/%d ###\n", chunk + 1, chunks);
	fflush(0);

	char *fin;
	if (asprintf(&fin, "%s-%d", tname_in, chunk) == -1) {
		perror("asprintf");
		exit(1);
	}
	FILE *fpin = fopen(fin, "r");
	if (!fpin) {
		perror("fopen");
		exit(1);
	}

	char *fout;
	if (asprintf(&fout, "%s-%d", tname_out, chunk) == -1) {
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

typedef struct node_t {
	struct node_t *next;
	char *domain;
} Node;

#define MAXHASH 8192
Node *hlist[MAXHASH] = {NULL};

// djb2 hash function by Dan Bernstein
static inline unsigned hash(const char *str, unsigned array_cnt) {
	unsigned hash = 5381;
	int c;

	while ((c = *str++) != '\0')
		hash = ((hash << 5) + hash) ^ c; // hash * 33 ^ c

	return (hash & (array_cnt - 1));
}

// returns 1 if adding to the hash table; returns 0 if already there
static int hlist_check(const char *domain) {
	assert(domain);
	unsigned h = hash(domain, MAXHASH);

	// check
	Node *ptr = hlist[h];
	while (ptr) {
		if (strcmp(ptr->domain, domain) == 0)
			return 0;
		ptr = ptr->next;
	}

	ptr = malloc(sizeof(Node));
	if (!ptr)
		errExit("malloc");
	memset(ptr, 0, sizeof(Node));
	ptr->domain = strdup(domain);
	if (!ptr->domain)
		errExit("strdup");
	ptr->next = hlist[h];
	hlist[h] = ptr;
	return 1;
}

static void build_output(const char *tname_out, int chunk) {
	char *tname;
	if (asprintf(&tname, "%s-%d", tname_out, chunk) == -1)
		errExit("asprintf");
	FILE *fp1 = fopen(tname, "r");
	assert(fp1);

	FILE *fp2 = NULL;
	if (arg_fout) {
		fp2 = fopen(arg_fout, "a");
		assert(fp2);
	}

	char buf[MAXBUF];
	while (fgets(buf, MAXBUF, fp1)) {
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		// comments
		char *start = ptr;
		if (*start == '#' || *start == '\0') { // preserve comments, blank lines
			if (fp2)
				fprintf(fp2, "%s\n", start);
			printf("%s\n", start);
		}
		else if (hlist_check(start)) {
			if (fp2)
				fprintf(fp2, "127.0.0.1 %s\n", start);
			printf("127.0.0.1 %s\n", start);
		}
	}

	fclose(fp1);
	unlink(tname);
	free(tname);
	if (fp2)
		fclose(fp2);
}


static void usage(void) {
	printf("nxdomain - version %s\n", VERSION);
	printf("nxdomain is an utility program that removes dead domains from a host list.\n");
	printf("\n");
	printf("Usage: nxdomain [options] file-in [file-out]\n");
	printf("\n");
	printf("If no file-out is specified, the results are printed on stdout.\n");
	printf("\n");
	printf("Options:\n");
	printf("\t--help, -?, -h - show this help screen.\n");
	printf("\n");
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Error: invalid number of arguments\n");
		usage();
		return 1;
	}

	int i;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-h") == 0 ||
		    strcmp(argv[i], "-?") == 0 ||
		    strcmp(argv[i], "--help") == 0) {
		 	usage();
		 	return 0;
		}
		else if (strcmp(argv[i], "--version") == 0) {
			printf("nxdomain - version %s\n", VERSION);
			return 0;
		}
		else if (arg_fin == NULL) {
			arg_fin = strdup(argv[i]);
			if (!arg_fin)
				errExit("strdup");
		}
		else if (arg_fout == NULL) {
			arg_fout = strdup(argv[i]);
			if (!arg_fout)
				errExit("strdup");
		}
		else {
			fprintf(stderr, "Error: invalid command\n");
			usage();
			return 1;
		}
	}

	// split input file
	char tname_in[128];
	sprintf(tname_in, "/run/user/%u/nxdomainXXXXXX", getuid());
	int tname_fd = mkstemp(tname_in);
	if (tname_fd == -1)
		errExit("mkstemp");
	close(tname_fd);
	char *tname_out;
	if (asprintf(&tname_out, "%sout", tname_in) == -1)
		errExit("asprintf");

	int chunks = split(arg_fin, tname_in);
	fflush(0);

	// process chunks
	for (i = 0; i < chunks; i += 4) {
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
				child = fork();
				if (child == -1) {
					perror("fork");
					exit(1);
				}
				if (child == 0) {
					run_chunk(i, chunks, tname_in, tname_out);
					exit(0);
				}
				else if ((i + 1) < chunks)
					run_chunk(i + 1, chunks, tname_in, tname_out);
				int wstatus;
				waitpid(child, &wstatus, 0);
				exit(0);
			}
			else if ((i + 2) < chunks)
				run_chunk(i + 2, chunks, tname_in, tname_out);
			int wstatus;
			waitpid(child, &wstatus, 0);
			exit(0);
		}
		else if ((i + 3) < chunks)
			run_chunk(i + 3, chunks, tname_in, tname_out);

		int wstatus;
		waitpid(child, &wstatus, 0);
	}

	// print result
	if (arg_fout) {
		int rv = unlink(arg_fout);
		(void) rv;
	}
	printf("\n\n\n");

	for (i = 0; i < chunks; i++)
		build_output(tname_out, i);

	printf("\n");
	unlink(tname_in);
	free(tname_out);

	return 0;
}
