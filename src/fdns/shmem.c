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

typedef struct dns_report_t {
	volatile uint32_t seq;	//sqence number used to detect data changes
#define MAX_HEADER 163 	// two full lines on a terminal screen, \n and \0
	char header[MAX_HEADER];
	int logindex;
#define MAX_LOG_ENTRIES 18 	// 18 lines on the screen in order to handle tab terminals
#define MAX_ENTRY_LEN 82 	// a full line on a terminal screen, \n and \0
	char logentry[MAX_LOG_ENTRIES][MAX_ENTRY_LEN];
} DnsReport;
DnsReport *report = NULL;

void shmem_open(int create) {
	int fd;

	// try to open the shared mem file
	if (create)
		fd = shm_open(PATH_STATS_FILE, O_RDWR, S_IRWXU );
	else
		fd = shm_open(PATH_STATS_FILE, O_RDONLY, S_IRWXU );

	if (fd == -1) {
		// the file doesn't exist, create it or exit
		if (create) {
			fd = shm_open(PATH_STATS_FILE, O_CREAT | O_EXCL | O_RDWR, S_IRWXO | S_IRWXU | S_IRWXG);
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
}

void shmem_store_stats(void) {
	assert(report);

	// server
	DnsServer *srv = server_get();
	assert(srv);


	// encryption status
	int i;
	for (i = 0; i < arg_workers; i++)
		if (encrypted[i] == 0)
			break;
	char *encstatus = (i == arg_workers) ? "ENCRYPTED" : "NOT ENCRYPTED";

	snprintf(report->header, MAX_HEADER,
		 "%s %s (SSL %.02lf ms, fallback %u), \n"
		 "requests %u, drop %u, cache %u, fwd %u\n",

		 srv->name,
		 encstatus,
		 stats.ssl_pkts_timetrace,
		 stats.fallback,

		 stats.rx,
		 stats.drop,
		 stats.cached,
		 stats.fwd);


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
	}
	else {
		snprintf(report->logentry[report->logindex], MAX_ENTRY_LEN, "%s", str);
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
static int inline check_shmem_file(void) {
	struct stat s;
	if (stat("/dev/shm/fdns-stats", &s) == -1)
		return 0;
	return 1;
}

static inline void print_line(const char *str) {
//red - printf("\033[31;1mHello\033[0m\n");
// 31 - red
// 91 -bright red
// 92 - bright green
	if (strstr(str, "Error"))
		printf("\033[91m%s\033[0m", str);
	else if (strstr(str, "fp-tracker"))
		printf("\033[91m%s\033[0m", str);
	else if (strstr(str, ", dropped"))
		printf("\033[92m%s\033[0m", str);
	else
		printf("%s", str);
}

// handling "fdns --monitor"
void shmem_monitor_stats(void) {
	while (1) {
		int first = 1;
		struct stat s;
		while (check_shmem_file() == 0) {
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
		shmem_open(0);

		uint32_t seq = 0;
		while (1) {
			if (check_shmem_file() == 0)
				break;

			// make a copy of the data in order to minimize the posibility of data changes durring printing
			DnsReport d;
			memcpy(&d, report, sizeof(DnsReport));
			seq = report->seq;

			ansi_clrscr();

			// print header
			printf("%s\n", d.header);

			// print log lines
			int i;
			for (i = d.logindex; i < MAX_LOG_ENTRIES; i++)
				print_line(d.logentry[i]);

			for (i = 0; i < d.logindex; i++)
				print_line(d.logentry[i]);

			// detect data changes and fdns going down using report->seq
			sleep(1);
			int cnt = 0;
			while (seq == report->seq && ++cnt < (SHMEM_KEEPALIVE * 3)) {
				sleep(1);
				if (check_shmem_file() == 0)
					break;
			}
			if (cnt >= (SHMEM_KEEPALIVE * 3)) { // declare fdns dead; it might never recover!
				printf("Error:\n");
				printf("\tSorry, fdns was shut down, it might never recover!\n");
				while (seq == report->seq)
					sleep(1);
			}
		}
	}
}
