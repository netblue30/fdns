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
static char *arg_server="1.1.1.1";

#define MAXBUF (10 * 1024)
static char outbuf[MAXBUF];

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
		if (asprintf(&cmd, "nslookup %s %s", start, arg_server) == -1) {
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
	printf("*** chunk %d/%d ***", chunk + 1, chunks);
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
	printf("\t--server=ip-address - use this DNS server, default 1.1.1.1 (Cloudflare).\n");
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
		else if (strncmp(argv[i], "--server=", 9) == 0) {
			uint32_t addr;
			if (atoip(argv[i]+9, &addr)) {
				fprintf(stderr, "Error: invalid server IPv4 address\n");
				usage();
				return 1;
			}
			arg_server = strdup(argv[i] + 9);
			if (!arg_server)
				errExit("strdup");
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
	char tname_in[32] = "/tmp/nxdomainXXXXXX";
	int tname_fd = mkstemp(tname_in);
	if (tname_fd == -1)
		errExit("mkstemp");
	close(tname_fd);
	char *tname_out;
	if (asprintf(&tname_out, "%sout", tname_in) == -1)
		errExit("asprintf");

	int chunks = split(arg_fin, tname_in);
	fflush(0);

	// frocess file chunks
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

	for (i = 0; i < chunks; i++) {
		if (arg_fout) {
			char *cmd;
			if (asprintf(&cmd, "cat %s-%d >> %s", tname_out, i, arg_fout) == -1)
				errExit("asprintf");
			int rv = system(cmd);
			(void) rv;
			free(cmd);
		}

		char *cmd;
		if (asprintf(&cmd, "cat %s-%d", tname_out, i) == -1)
			errExit("asprintf");
		int rv = system(cmd);
		(void) rv;
		free(cmd);
	}

	char *cmd;
	if (asprintf(&cmd, "rm %s-*", tname_out) == -1)
		errExit("asprintf");
	int rv = system(cmd);
	(void) rv;

	printf("\n");
	unlink(tname_in);
	free(tname_out);

	return 0;
}
