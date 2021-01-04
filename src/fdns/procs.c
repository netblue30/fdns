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

#include "fdns.h"
#include <dirent.h>

static void procs_dir_cleanup(void) {
	DIR *dir;
	if (!(dir = opendir("/run/fdns"))) {
		// sleep 2 seconds and try again
		sleep(2);
		if (!(dir = opendir("/proc"))) {
			fprintf(stderr, "Error: cannot open /proc directory\n");
			exit(1);
		}
	}

	struct dirent *entry;
	while ((entry = readdir(dir))) {
		if (*entry->d_name == '.')
			continue;

		char *fname;
		if (asprintf(&fname, "/proc/%s", entry->d_name) == -1)
			errExit("asprintf");
		if (access(fname, R_OK)) {
			printf("cleaning %s\n", entry->d_name);
			fflush(0);

			char *runfname;
			if (asprintf(&runfname, "/run/fdns/%s", entry->d_name) == -1)
				errExit("asprintf");
			int rv = unlink(runfname);
			(void) rv;
			free(runfname);
		}
		free(fname);
	}

	closedir(dir);
}


void procs_exit(void) {
	pid_t pid = getpid();
	char *runfname;
	if (asprintf(&runfname, "/run/fdns/%d", pid) == -1)
		errExit("asprintf");
	int rv = unlink(runfname);
	(void) rv;
	free(runfname);
}

void procs_add(void) {
	assert(getuid() == 0);

	struct stat s;
	if (stat(PATH_RUN_FDNS, &s) ) {
		if (mkdir(PATH_RUN_FDNS, 0755) == -1) {
			fprintf(stderr, "Error: cannot create %s directory\n", PATH_RUN_FDNS);
			exit(1);
		}
	}
	procs_dir_cleanup();

	pid_t pid = getpid();
	char *fname;
	if (asprintf(&fname, "/run/fdns/%d", pid) == -1)
		errExit("asprintf");

	FILE *fp = fopen(fname, "w");
	if (fp == NULL) {
		fprintf(stderr, "Error: cannot create %s file\n", fname);
		exit(1);
	}

	char *tmp = (arg_proxy_addr) ? arg_proxy_addr : DEFAULT_PROXY_ADDR;
	if (arg_proxy_addr_any)
		tmp = "0.0.0.0";
	fprintf(fp, "%s\n", tmp);
	fclose(fp);
	free(fname);
	atexit(procs_exit);
}

int procs_addr_default = 0;
int procs_addr_loopback = 0;
char *procs_addr_real = NULL;

void procs_list(void) {
	DIR *dir;
	if (!(dir = opendir("/run/fdns"))) {
		// sleep 2 seconds and try again
		sleep(2);
		if (!(dir = opendir("/proc")))
			return;
	}

	struct dirent *entry;
	int procs_addr_flag = 0;
	while ((entry = readdir(dir))) {
		if (*entry->d_name == '.')
			continue;

		char *fname;
		if (asprintf(&fname, "/proc/%s", entry->d_name) == -1)
			errExit("asprintf");
		if (access(fname, R_OK) == 0) {
			char *runfname;
			if (asprintf(&runfname, "/run/fdns/%s", entry->d_name) == -1)
				errExit("asprintf");
			printf("pid %s,", entry->d_name);
			FILE *fp = fopen(runfname, "r");
			if (fp) {
				char buf[MAXBUF];
				if (fgets(buf, MAXBUF, fp)) {
					char *ptr = strchr(buf, '\n');
					if (ptr)
						*ptr = '\0';

					if (!procs_addr_flag) {
						if (strcmp(buf, "127.1.1.1") == 0) {
							procs_addr_default = 1;
							procs_addr_flag = 1;
						}
						else if (strcmp(buf, "127.0.0.1") == 0) {
							procs_addr_loopback = 1;
							procs_addr_flag = 1;
						}
						else if (!procs_addr_real) {
							procs_addr_real = strdup(buf);
							if (!procs_addr_real)
								errExit("strdup");
						}
					}

					printf(" address %s", buf);
					if (strcmp(buf, DEFAULT_PROXY_ADDR) == 0)
						printf(" (default)");
				}
			}
			printf("\n");
			fclose(fp);
			free(runfname);
		}
		free(fname);
	}
	closedir(dir);
	printf("\n");
}
