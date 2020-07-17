#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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

// supported formats:
//    - lines in regular hosts files with ip addresses of 127.0.0.1 and 0.0.0.0
//    - lists of domain names, one domain per line
void filter_test_list(const char *fname) {
	assert(fname);
	FILE *fp = fopen(fname, "r");
	if (!fp) {
		perror("fopen");
		exit(1);
	}

	char buf[MAXBUF];
	while (fgets(buf, MAXBUF, fp)) {
		char *ptr = strchr(buf, '\n');
		if (ptr)
			*ptr = '\0';
		ptr = buf;
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		// comments
		char *start = ptr;
		if (*start == '#' || *start == '\0') { // preserve comments
			printf("%s\n", start);
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

		fprintf(stderr, "Testing %s\n", start);
		char *output = run_program(cmd);
		assert(output);
		if (strstr(output, "NXDOMAIN") == NULL) {
			fprintf(stderr, "\t127.0.0.1 %s\n", start);
			printf("127.0.0.1 %s\n", start);
		}
		free(cmd);
	}

	fclose(fp);
}

static void usage(void) {
	printf("nxdomain - simple utility to remove domains from a list based on NXDOMAIN reported by nslookup\n");
	printf("Usage: nxdomain file\n");
}

int main(int argc, char **argv) {
	if (argc != 2) {
		usage();
		return 1;
	}
	if (strcmp(argv[1], "-h") == 0) {
		usage();
		return 0;
	}

	filter_test_list(argv[1]);
	return 0;
}
