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

typedef struct cache_entry_t {
	struct cache_entry_t *next;
#define MAX_TTL 300
	int16_t  ttl;
	uint16_t len;
	int type; // 0 - ipv4,, 1 - ipv6
	char name[CACHE_NAME_LEN + 1];
#define MAX_REPLY 900
	uint8_t reply[MAX_REPLY];
} CacheEntry;	// not more than 1024

#define MAX_HASH_ARRAY 256
static CacheEntry *clist[MAX_HASH_ARRAY];
static char cname[CACHE_NAME_LEN + 1] = {0};
static int cname_type;	// 0 - ipv4, 1 - ipv6
static uint8_t creply[MAX_REPLY];

static inline void clean_entry(CacheEntry *ptr) {
	ptr->next = NULL;
	ptr->ttl = 0;
	ptr->type = 0;
	ptr->name[0] = '\0';
}

// djb2 hash function by Dan Bernstein
static inline int hash(const char *str, int type) {
	uint32_t hash = 5381;
	int c;

	while ((c = *str++) != '\0')
		hash = ((hash << 5) + hash) ^ c; // hash * 33 ^ c

	return (int) ((hash & (MAX_HASH_ARRAY - 1)) ^ type);
}

void cache_init(void) {
	memset(&clist[0], 0, sizeof(clist));
	memset(cname, 0, sizeof(cname));
}

void cache_set_name(const char *name, int ipv6) {
	assert(name);
	strncpy(cname, name, CACHE_NAME_LEN);
	cname[CACHE_NAME_LEN] = '\0';
	cname_type = ipv6;
}

static int mcnt = 0;
void cache_set_reply(uint8_t *reply, ssize_t len) {
	assert(reply);
	if (len > MAX_REPLY || *cname == '\0')
		return;

	int h = hash(cname, cname_type);
	CacheEntry *ptr = malloc(sizeof(CacheEntry));
	if (!ptr)
		errExit("malloc");
	clean_entry(ptr);
	mcnt++;

	ptr->len = len;
	ptr->type = cname_type;
	assert(sizeof(cname) == sizeof(ptr->name));
	memcpy(ptr->name, cname, sizeof(cname));
	memcpy(ptr->reply, reply, len);
	ptr->ttl = MAX_TTL;

	ptr->next = clist[h];
	clist[h] = ptr;
}


uint8_t *cache_check(uint16_t id, const char *name, ssize_t *lenptr, int ipv6) {
	assert(name);
	int h = hash(name, ipv6);
	CacheEntry *ptr = clist[h];
	while (ptr) {
		if (strcmp(ptr->name, name) == 0 && ptr->type == ipv6) {
			// store the reply locally
			assert(ptr->len);
			assert(ptr->len < MAX_REPLY);
			memcpy(creply, ptr->reply, ptr->len);
			// set id
			id = htons(id);
			memcpy(creply, &id, 2);
			// set length
			*lenptr = ptr->len;

			return creply;
		}

		ptr = ptr->next;
	}

	return NULL;
}

void cache_timeout(void) {
	int i;

	int cnt = 0;
	for (i = 0; i < MAX_HASH_ARRAY; i++) {
		CacheEntry *ptr = clist[i];
		CacheEntry *last = NULL;

		while (ptr) {
			ptr->ttl--;
			if (ptr->ttl <= 0) {
				if (last == NULL)
					clist[i] = ptr->next;
				else
					last->next = ptr->next;


				CacheEntry *tmp = ptr;
				ptr = ptr->next;
				free(tmp);
				mcnt--;
			}
			else {
				last = ptr;
				ptr = ptr->next;
				cnt++;
			}
		}
	}

	assert(cnt == mcnt);
}
