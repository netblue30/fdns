/*
 * Copyright (C) 2014-2019 fdns Authors
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
	DnsServer *srv = dns_get_server();
	assert(srv);


	// encryption status
	int i;
	for (i = 0; i < arg_workers; i++)
		if (encrypted[i] == 0)
			break;
	char *encstatus = (i == arg_workers)? "ENCRYPTED": "NOT ENCRYPTED";

	snprintf(report->header, MAX_HEADER,
		 "PID %d, requests %u, dropped %u, fallback %u, cached %u\n"
		 "%s %s\n",

		 getpid(),
		 stats.rx,
		 stats.drop,
		 stats.fallback,
		 stats.cached,
		 srv->name,
		 encstatus);
	report->seq++;
}

void shmem_store_log(const char *str) {
	assert(str);
	snprintf(report->logentry[report->logindex], MAX_ENTRY_LEN, "%s", str);
	if (++report->logindex >= MAX_LOG_ENTRIES)
		report->logindex = 0;
	*report->logentry[report->logindex] = '\0';
	report->seq++;
}

// handling "fdns --monitor"
void shmem_monitor_stats(void) {
	shmem_open(0);
	uint32_t seq = 0;

	while (1) {
		// make a copy of the data in order to minimize the posibility of data changes durring printing
		DnsReport d;
		memcpy(&d, report, sizeof(DnsReport));

		ansi_clrscr();

		// print header
		printf("%s\n", d.header);

		// print log lines
		int i;
		for (i = d.logindex; i < MAX_LOG_ENTRIES; i++)
			printf("%s", d.logentry[i]);
		for (i = 0; i < d.logindex; i++)
			printf("%s", d.logentry[i]);

		// detect data changes using report->seq
		seq = report->seq;
		sleep(1);
		int cnt = 0;
		while (seq == report->seq && ++cnt < 10)
			sleep(1);
	}
}
