/*
 * Copyright (C) 2019-2025 FDNS Authors
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

typedef struct unlisted_t {
	struct unlisted_t *next;
	char *name;
} UnlistedElem;

static UnlistedElem *unlisted = NULL;

void *unlisted_find(const char *name) {
	assert(name);
	UnlistedElem *ptr = unlisted;

	while (ptr) {
		if (strcmp(name, ptr->name) == 0)
			return ptr;
		ptr = ptr->next;
	}

	return NULL;
}

void unlisted_add(const char *name) {
	assert(name);
	if (server_print_unlist && arg_id == -1 && arg_debug)
		printf("Unlisting %s\n", name);

	UnlistedElem *ptr = malloc(sizeof(UnlistedElem));
	if (!ptr)
		errExit("malloc");
	memset(ptr, 0, sizeof(UnlistedElem));
	ptr->name = strdup(name);
	if (!ptr->name)
		errExit("strdup");

	if (unlisted == NULL)
		unlisted = ptr;
	else {
		ptr->next = unlisted;
		unlisted = ptr;
	}
}
