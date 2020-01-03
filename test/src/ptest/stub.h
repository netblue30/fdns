/*
 * Copyright (C) 2019-2020 fdns Authors
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
#ifndef STUB_H
#define STUB_H
#include "../../../src/fdns/fdns.h"

int arg_allow_all_queries = 0;
int arg_nofilter = 0;
int arg_ipv6 = 0;
Stats stats;
SSLState ssl_state = SSL_OPEN;

// remote logging (worker processes)
void rlogprintf(const char *format, ...) {
	va_list valist;
	va_start(valist, format);
	vprintf(format, valist);
	va_end(valist);
	fflush(0);
}

const char *filter_blocked(const char *str, int verbose) {
	(void) str;
	(void) verbose;
	return 0;
}

void cache_set_name(const char *name, int ipv6) {
	(void) name;
	(void) ipv6;
}

uint8_t *cache_check(uint16_t id, const char *name, ssize_t *lenptr, int ipv6) {
	(void) id;
	(void) name;
	(void) lenptr;
	(void) ipv6;
	return NULL;
}

int forwarder_check(const char *domain, unsigned len) {
	(void) domain;
	(void) len;
	return 0;
}

#endif