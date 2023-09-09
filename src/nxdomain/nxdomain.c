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
#include <time.h>

static char *arg_fin = NULL;
static char *arg_fout = NULL;
#define SERVER_DEFAULT "1.1.1.1"
char *arg_server = SERVER_DEFAULT;
#define TIMEOUT_DEFAULT 5	// resolv.com, dig, and nslookup are using a default timeout of 5
int arg_timeout = TIMEOUT_DEFAULT;
int arg_chunk_size = FILE_CHUNK_SIZE;
char current_chunk[FILE_CHUNK_SIZE][LINE_MAX];



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

	char buf[LINE_MAX];
	while (fgets(buf, LINE_MAX, fp1)) {
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
		else  {
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




static void test(FILE *fpout, int chunk_no) {
	assert(fpout);

	char buf[LINE_MAX];
	int i = 0;
	int j = 0;
	char *start = "not running";
	for (i = 0; i < arg_chunk_size && *current_chunk[i] != '\0'; i++) {
		char*buf = current_chunk[i];
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		// empty lines
		if (*ptr == '\0') {
			fprintf(fpout, "\n");
			continue;
		}

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
			fprintf(stderr, "E");
			fflush(0);
			continue;
		}

		// domains no longer 80 chars
		if (strlen(start) > 80) {
			fprintf(stderr, "L");
			fflush(0);
			continue;
		}

		// check subdomains
		ptr = start;
		int sub_cnt = 0;
		int sub_size = 0;
		while (*ptr) {
			if (*ptr == '.') {
				if (++sub_cnt > 65)
					break;
				sub_size = 0;
			}
			else {
				sub_size++;
				if (sub_size > 63)
					break;
			}
			ptr++;
		}
		if (*ptr != '\0' || sub_cnt == 0) {
			fprintf(stderr, "E");
			fflush(0);
			continue;
		}


		// send DNS request
		usleep(100000);	// maximum 10xMAX_CHUNKS requests per second
		int rv = resolver(start);
//printf("%s\n", start);
		if (rv == 0) {
			j++;
			fprintf(stderr, "*");
			fflush(0);
			fprintf(fpout, "%s\n", start);
			fflush(0);
		}
		else if (rv == 2) {
			fprintf(stderr, "T");
			fprintf(fpout, "#@timeout 127.0.0.1 %s\n", start);
			fflush(0);
		}
	}
	printf("# chunk %d: %d removed #", chunk_no, i - j);
	fflush(0);
}



static void run_chunk(int chunk_no, const char *tname_out) {
	fprintf(stderr, "\n# chunk %d #\n", chunk_no);
	fflush(0);

	char *fout;
	if (asprintf(&fout, "%s-%d", tname_out, chunk_no) == -1) {
		perror("asprintf");
		exit(1);
	}
	FILE *fpout = fopen(fout, "w");
	if (!fpout) {
		perror("fopen out");
		exit(1);
	}

	test(fpout, chunk_no);
	fclose(fpout);
	free(fout);
}


static int load_chunk(FILE *fp, int chunk_no) {
	assert(fp);

	int i;
	for (i = 0; i < FILE_CHUNK_SIZE; i++)
		*current_chunk[i] = '\0';

	i = 0;
	while (i < arg_chunk_size) {
		if (fgets(current_chunk[i], LINE_MAX, fp) == NULL)
			return 1;
		i++;
	}

	return 0;
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
	printf("\t--chunk-size=number - number of domains in a chunk of input data, default %d\n", FILE_CHUNK_SIZE);
	printf("\t--help, -?, -h - show this help screen.\n");
	printf("\t--server=IP_ADDRESS - DNS server IP address, default Cloudflare %s\n", SERVER_DEFAULT);
	printf("\t--timeout=seconds - number of seconds to wait for a response form the server, default %d\n", TIMEOUT_DEFAULT);
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
		else if (strncmp(argv[i], "--server=", 9) == 0)
			arg_server = argv[i] + 9;
		else if (strncmp(argv[i], "--timeout=", 10) == 0) {
			arg_timeout = atoi(argv[i] + 10);
			if (arg_timeout < 1) {
				fprintf(stderr, "Error: use a positive number\n");
				exit(1);
			}
		}
		else if (strncmp(argv[i], "--chunk-size=", 13) == 0) {
			arg_chunk_size = atoi(argv[i] + 13);
			if (arg_chunk_size < 1 || arg_chunk_size > 500) {
				fprintf(stderr, "Error: use a number between 1 and 500\n");
				exit(1);
			}
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


	time_t start = time(NULL);
	fprintf(stderr, "%s", ctime(&start));
	fprintf(stderr, "Input file %s\n", arg_fin);
	fprintf(stderr, "Output file %s\n", (arg_fout)? arg_fout: "stdout");
	fprintf(stderr, "Server %s, timeout %d, max %d queries per second, %d domains in a chunk of data\n",
		arg_server, arg_timeout, 10 * MAX_CHUNKS, arg_chunk_size);

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

	FILE *fp = fopen(arg_fin, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot open %s\n", arg_fin);
		exit(1);
	}

	int active_chunks = 0;
	i = 0;
	while (1) {
		int last_chunk = load_chunk(fp, i);

		pid_t child = fork();
		if (child == -1) {
			perror("fork");
			exit(1);
		}
		if (child == 0) {
			fclose(fp);
			run_chunk(i, tname_out);
			exit(0);
		}

		if (last_chunk)
			break;
		i++;
		active_chunks++;
		if (active_chunks >= MAX_CHUNKS ) {
			int status;
			wait(&status);
			active_chunks--;
		}
	}
	fclose(fp);

	pid_t wpid;
	int status;
	while ((wpid = wait(&status)) > 0)
		printf("#waiting#\n");

	// print result
	if (arg_fout) {
		int rv = unlink(arg_fout);
		(void) rv;
	}
	printf("\n\n\n");

	int chunks = i + 1;
	for (i = 0; i < chunks; i++)
		build_output(tname_out, i);

	printf("\n");
	unlink(tname_in);
	free(tname_out);
	time_t end = time(NULL);
	unsigned delta = end - start;
	printf("\nrun time %u minutes\n", delta / 60);

	return 0;
}
