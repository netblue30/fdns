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
#ifndef LINT_H
#define LINT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

typedef struct __attribute__((__packed__)) dns_header_t {
	uint16_t id;
	uint16_t flags;
	uint16_t questions;
	uint16_t answer;
	uint16_t authority;
	uint16_t additional;
} DnsHeader;

typedef struct dns_question_t {
// maximum domain name including the first label length byte and terminating '\0'
#define DNS_MAX_DOMAIN_NAME 255
	char domain[DNS_MAX_DOMAIN_NAME];
	uint16_t type;	// RR type requested
	unsigned len;	// question length
	unsigned dlen;	// domain name length (len - 6)
} DnsQuestion;

typedef struct __attribute__((__packed__)) dns_rr_t {
	uint16_t type;
	uint16_t cls;
	uint32_t ttl;
	uint16_t rlen;
} DnsRR;

// error checking
#define DNSERR_OK 0
#define DNSERR_INVALID_HEADER 1
#define DNSERR_INVALID_DOMAIN 2
#define DNSERR_INVALID_CLASS 3
#define DNSERR_NXDOMAIN 4
#define DNSERR_MULTIPLE_QUESTIONS 5
#define DNSERR_INVALID_PKT_LEN 6
#define DNSERR_MAX 7		// always the last one
int lint_error(void);
const char *lint_err2str(void);

DnsHeader *lint_header(uint8_t **pkt, uint8_t *last);
DnsQuestion *lint_question(uint8_t **pkt, uint8_t *last);
int lint_rx(uint8_t *pkt, unsigned len);
#endif
