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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// download https://github.com/EFForg/privacybadger/blob/master/src/data/seed.json
// run the program
// merge the result with etc/trackers

#define MAXBUF 8192

int main(void) {
	FILE *fp = fopen("seed.json", "r");
	if (!fp) {
		perror("fopen");
		exit(1);
	}

	char buf[MAXBUF];
	char domain[MAXBUF];

	while (fgets(buf, MAXBUF, fp)) {
		// remove \n
		char *ptr = strchr(buf, '\n');
		if (*ptr)
			*ptr = '\0';

		// skip some lines
		if (*buf == '\0' ||
		    strstr(buf, "\"action_map\"") ||
		    strstr(buf, "\"nextUpdateTime\"") ||
		    strstr(buf, "\"dnt\""))
		    	continue;

		// not interested in snitch_map
		if (strstr(buf, "\"snitch_map\""))
			break;

		// detect domain block
		if ((ptr = strstr(buf, "\": {")) != NULL){
			*ptr = '\0';
			ptr = strchr(buf, '"');
			if (!ptr) {
				fprintf(stderr, "Error: unsupported seed.json format\n");
				exit(1);
			}
			ptr++;

			strcpy(domain, ptr);
			continue;
		}

		// blocked domain
		if (strstr(buf, "\"heuristicAction\": \"block\","))
			printf("%s\n", domain);
	}
	fclose(fp);

	return 0;
}