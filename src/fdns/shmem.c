/*
 * Copyright (C) 2019-2020 FDNS Authors
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
#include "fdns.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>

typedef struct dns_report_t {
	volatile uint32_t seq;	//sqence number used to detect data changes
#define MAX_ENTRY_LEN 82 	// a full line on a terminal screen, \n and \0
	char header1[MAX_ENTRY_LEN];
	char header2[MAX_ENTRY_LEN];
	int logindex;
#define MAX_LOG_ENTRIES 512 	// 18 lines on the screen in order to handle tab terminals
	time_t tstamp[MAX_LOG_ENTRIES];
	char logentry[MAX_LOG_ENTRIES][MAX_ENTRY_LEN];
} DnsReport;
DnsReport *report = NULL;

void shmem_open(int create, const char *proxy_addr) {
	assert(proxy_addr);
	int fd;

	// build file name
	char *fname;
	if (asprintf(&fname, PATH_STATS_FILE "-%s", proxy_addr) == -1)
		errExit("asprintf");

	// try to open the shared mem file
	if (create)
		fd = shm_open(fname, O_RDWR, S_IRWXU );
	else
		fd = shm_open(fname, O_RDONLY, S_IRWXU );

	if (fd == -1) {
		// the file doesn't exist, create it or exit
		if (create) {
			fd = shm_open(fname, O_CREAT | O_EXCL | O_RDWR, S_IRWXO | S_IRWXU | S_IRWXG);
			if (fd == -1)
				errExit("shm_open");
		}
		else {
			fprintf(stderr, "Cannot find stats file, probably fdns is not running\n");
			exit(1);
		}
	}

	if (create)
		report = mmap(0, sizeof(DnsReport), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
	else
		report = mmap(0, sizeof(DnsReport), PROT_READ, MAP_SHARED, fd, 0 );
	if (report == (void *) - 1)
		errExit("mmap");

	// set the size and initialize sequence number
	if (create) {
		int v = ftruncate(fd, sizeof(DnsReport));
		if (v == -1)
			errExit("ftruncate");
		memset(report, 0, sizeof(DnsReport));
		report->seq = 0;
	}

	free(fname);
}

void shmem_store_stats(const char *proxy_addr) {
	assert(report);
	assert(proxy_addr);

	// server
	DnsServer *srv = server_get();
	assert(srv);


	// encryption status
	int i;
	for (i = 0; i < arg_resolvers; i++)
		if (encrypted[i] == 0)
			break;
	char *encstatus = (i == arg_resolvers) ? "ENCRYPTED" : "NOT ENCRYPTED";

	if (arg_fallback_only)
		snprintf(report->header1, MAX_ENTRY_LEN,
			 "%s %s %s",
			 proxy_addr,
			 FALLBACK_SERVER,
			 encstatus);

	else {
		char *transport = "DoH";
		if (srv->transport && strstr(srv->transport, "dot"))
			transport = "DoT";
		snprintf(report->header1, MAX_ENTRY_LEN,
			 "%s %s %s (%s %.02lf ms, %d s)",
			 proxy_addr,
			 srv->name,
			 encstatus,
			 transport,
			 stats.ssl_pkts_timetrace,
			 srv->keepalive_max);
	}
	snprintf(report->header2, MAX_ENTRY_LEN,
		 "requests %u, drop %u, cache %u, fwd %u, fallback %u",
		 stats.rx,
		 stats.drop,
		 stats.cached,
		 stats.fwd,
		 stats.fallback);

	fflush(0);
	report->seq++;
}

static char lastentry[MAX_ENTRY_LEN] = {'\0'};
static int lastentry_cnt = 1;
static int lastentry_index = 0;
void shmem_store_log(const char *str) {
	assert(str);

	if (strcmp(lastentry, str) == 0) {
		lastentry_cnt++;
		snprintf(report->logentry[lastentry_index], MAX_ENTRY_LEN, "%dx  %s", lastentry_cnt, str);
		report->tstamp[lastentry_index] = time(NULL);
	}
	else {
		snprintf(report->logentry[report->logindex], MAX_ENTRY_LEN, "%s", str);
		report->tstamp[report->logindex] = time(NULL);
		snprintf(lastentry, MAX_ENTRY_LEN, "%s", str);
		lastentry_cnt = 1;
		lastentry_index = report->logindex;
		if (++report->logindex >= MAX_LOG_ENTRIES)
			report->logindex = 0;
		*report->logentry[report->logindex] = '\0';
	}
	report->seq++;
}

void shmem_keepalive(void) {
	report->seq++;
}


// return 1 if file is present
inline static int check_shmem_file(const char *proxy_addr) {
	assert(proxy_addr);

	// build file name
	char *fname;
	if (asprintf(&fname, "/dev/shm" PATH_STATS_FILE "-%s", proxy_addr) == -1)
		errExit("asprintf");

	struct stat s;
	if (stat(fname, &s) == -1) {
		free(fname);
		return 0;
	}
	free(fname);
	return 1;
}

static inline void print_line(const char *str, int col) {
//red - printf("\033[31;1mHello\033[0m\n");
// 31 - red
// 91 -bright red
// 92 - bright green
	if (strstr(str, "Error"))
		printf("\033[91m%.*s\033[0m", col, str);
	else if (strstr(str, "fp-tracker  "))
		printf("\033[91m%.*s\033[0m", col, str);
	else if (strstr(str, "doh  "))
		printf("\033[91m%.*s\033[0m", col, str);
	else if (strstr(str, ", dropped") || strstr(str, "refused by service provider"))
		printf("\033[92m%.*s\033[0m", col, str);
	else
		printf("%.*s", col, str);
#ifdef HAVE_GCOV
	__gcov_flush();
#endif
}


// detect terminal window size change
static volatile int need_resize = 0;
static void wins_resize_sighandler (int dont_care_sig) {
	(void)dont_care_sig;
	need_resize = 1;
}

// handling "fdns --monitor"
void shmem_monitor_stats(const char *proxy_addr) {
	signal(SIGCONT,  wins_resize_sighandler);
	signal(SIGWINCH, wins_resize_sighandler);

	if (proxy_addr == NULL)
		proxy_addr = DEFAULT_PROXY_ADDR;

	while (1) {
#ifdef HAVE_GCOV
		__gcov_flush();
#endif
		int first = 1;
		while (check_shmem_file(proxy_addr) == 0) {
			if (first) {
				printf("Waiting for fdns to start...");
				fflush(0);
				first = 0;
			}
			else {
				printf(".");
				fflush(0);
				sleep(1);
			}
		}
		shmem_open(0, proxy_addr);

		uint32_t seq = 0;
		while (1) {
			if (check_shmem_file(proxy_addr) == 0)
				break;

			struct winsize sz;
			int col = 80;
			int row = 24;
			if (isatty(STDIN_FILENO)) {
				if (!ioctl(0, TIOCGWINSZ, &sz)) {
					col  = sz.ws_col;
					row = sz.ws_row;
				}
			}

			// make a copy of the data in order to minimize the posibility of data changes durring printing
			DnsReport d;
			memcpy(&d, report, sizeof(DnsReport));
			seq = report->seq;

			ansi_clrscr();

			// print header
			printf("%.*s\n", col, d.header1);
			printf("%.*s\n", col, d.header2);
			printf("\n");

			// print log lines
			int i;
			int logrows = MAX_LOG_ENTRIES;
			if ((row - 4) > 0 && (row - 4) < MAX_LOG_ENTRIES)
				logrows = row - 4;

			int index = d.logindex - logrows;
			for (i = 0; i < logrows; i++, index++) {
				int position = index;
				if (index < 0)
					position += MAX_LOG_ENTRIES;
				print_line(d.logentry[position], col);
			}
			fflush(0);

			// detect data changes and fdns going down using report->seq
			int cnt = 0;
			while (seq == report->seq && ++cnt < (SHMEM_KEEPALIVE * 3)) {
				if (check_shmem_file(proxy_addr) == 0)
					break;
				sleep(1); // interrupted by SIGWINCH/SIGCONT
				if (need_resize)
					break;

			}
			if (cnt >= (SHMEM_KEEPALIVE * 3)) { // declare fdns dead; it might never recover!
				printf("Error:\n");
				printf("\tSorry, fdns was shut down, it might never recover!\n");
				while (seq == report->seq)
					sleep(1);
			}

			need_resize = 0;
		}
	}
}

void shm_timeout(void) {
	static int cnt = 0;
	if (!report)
		return;
	if (++cnt < 10) // run the cleanup every 10 seconds
		return;
	time_t t = time(NULL);
	if (arg_log_timeout != 0)
		t -= arg_log_timeout * 60;
	else
		t -= LOG_TIMEOUT_DEFAULT * 60;

	int i;
	for (i = 0; i < MAX_LOG_ENTRIES; i++) {
		if (report->tstamp[i] != 0 && report->tstamp[i] < t) {
			report->tstamp[i] = 0;
			memset(report->logentry[i], 0, MAX_ENTRY_LEN);
		}
	}
}
