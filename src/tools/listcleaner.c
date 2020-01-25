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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXBUF 2048

static void usage(void) {
	printf("Usage: listcleaner file(s)\n");
}

int main(int argc, char **argv) {
	if (argc < 2) {
		usage();
		return 1;
	}

	int i;
	for (i = 1; i < argc; i++) {
		char buf[MAXBUF];
		FILE *fp = fopen(argv[i], "r");
		if (!fp) {
			fprintf(stderr, "cannot open %s\n", argv[i]);
			exit(1);
		}

		while (fgets(buf, 2048, fp)) {
			// remove '\n'
			char *ptr = strchr(buf, '\n');
			if (ptr)
				*ptr = '\0';
//			printf("127.0.0.1 %s\n", buf);
//			continue;

			// check length
			int len = strlen(buf);
			if (len < 4)
				continue;

			// extract domain name
			if (buf[0] != '|' || buf[1] != '|')
				continue;

			if (buf[len -1] != '^')
				continue;
			buf[len - 1] = '\0';
			printf("127.0.0.1 %s\n", buf + 2);
		}
	}

	return 0;
}
