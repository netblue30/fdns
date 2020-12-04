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

// database of DNS requests; this code is not re-entrant

typedef struct db_elem_t {
	uint8_t active;
	uint8_t timeout;
#define ID_SIZE 2 	// 2 bytes matching DNS id
	uint8_t *buf[ID_SIZE];
	struct db_elem_t *next;
	struct sockaddr_in addr;
	int pool_index;
} DbElem;

#define MAX_HASH_ARRAY 256
static DbElem db[MAX_HASH_ARRAY];

void dnsdb_init(void) {
	memset(&db[0], 0, sizeof(db));
}

static inline int hash(const uint8_t *buf) {
	uint8_t h = 0xac;
	int i;
	for (i = 0; i < ID_SIZE; i++, buf++)
		h ^= *buf;
	if(arg_debug)
		printf("hash %u\n", h);
	return (int) h;
}

struct sockaddr_in *dnsdb_retrieve(int pool_index, uint8_t *buf) {
	assert(pool_index < MAX_FALLBACK_POOL);
	assert(buf);
	if (arg_debug)
		printf("dbretrieve %u %u, pool index %d\n", buf[0], buf[1], pool_index);
	int h = hash(buf);
	assert(h < MAX_HASH_ARRAY);

	DbElem *ptr = &db[h];
	assert(ptr);
	do {
		if (ptr->active && memcmp(ptr->buf, buf, ID_SIZE) == 0 && pool_index == ptr->pool_index) {
			ptr->active = 0;
			return &ptr->addr;
		}
		ptr = ptr->next;
	}
	while (ptr);
	if(arg_debug)
		printf("search failed\n");
	return NULL;
}

void dnsdb_store(int pool_index, uint8_t *buf, struct sockaddr_in *addr) {
	assert(pool_index < MAX_FALLBACK_POOL);
	assert(buf);
	assert(addr);
	if (arg_debug)
		printf("dbstore %u, %u, pool_index %d\n", buf[0], buf[1], pool_index);

	int h = hash(buf);
	assert(h < MAX_HASH_ARRAY);

	DbElem *ptr = &db[h];
	assert(ptr);
	DbElem *found = NULL;
	do {
		if (!ptr->active || (ptr->active && memcmp(buf, ptr->buf, ID_SIZE) == 0 && ptr->pool_index == pool_index)) {
			found = ptr;
			break;
		}
		ptr = ptr->next;
	}
	while (ptr);

	if (!found) {
		if(arg_debug)
			printf("allocating new db element\n");
		// allocate a new element and place it at the end of the list
		found = malloc(sizeof(DbElem));
		if (!found)
			errExit("malloc");
		memset(found, 0, sizeof(DbElem));
		ptr = &db[h];
		while (ptr->next)
			ptr = ptr->next;
		ptr->next = found;
	}

	// set the hash table entry
	memcpy(found->buf, buf, ID_SIZE);
	memcpy(&found->addr, addr, sizeof(struct sockaddr_in));
	found->active = 1;
	found->timeout = FALLBACK_TIMEOUT;
	found->pool_index = pool_index;
}

int dnsdb_timeout(void) {
	int i;
	int cnt = 0;
	for (i = 0; i < MAX_HASH_ARRAY; i++) {
		DbElem *ptr = &db[i];
		while (ptr) {
			if (ptr->active) {
				if (--ptr->timeout <= 0)
					ptr->active = 0;
				else
					cnt++;
			}
			ptr = ptr->next;
		}
	}
	return cnt;
}

