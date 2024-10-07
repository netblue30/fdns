/*
*Copyright (C) 2019 - 2021 FDNS Authors
*
*This file is part of fdns project
*
*This program is free software:
you can redistribute it and / or modify
*it under the terms of the GNU General Public License as published by
*the Free Software Foundation, either version 3 of the License, or
*(at your option) any later version.
*
*This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY;
without even the implied warranty of
*MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*GNU General Public License for more details.
*
*You should have received a copy of the GNU General Public License
*along with this program.  If not, see < https : //www.gnu.org/licenses/>.
*/
#include "fdns.h"
 #include <signal.h>

void restart(void) {
	// find default proxy pid
	pid_t default_pid = 0;
	procs_list(&default_pid);
	if (!default_pid) {
		fprintf(stderr, "Error: no default proxy found\n");
		exit(1);
	}

	// extract command line
	char *fname;
	if (asprintf(&fname, "/proc/%d/cmdline", default_pid) == -1)
		errExit("asprintf");
	FILE *fp = fopen(fname, "r");
	if (!fp) {
		fprintf(stderr, "Error: cannot open %s file\n", fname);
		exit(1);
	}

	fprintf(stderr, "Restarting %d proxy\n", default_pid);
	int rv = kill(default_pid, SIGUSR1);
	if (rv) {
		fprintf(stderr, "Error: cannot kill existing default proxy, not enough permissions\n");
		exit(1);
	}
}