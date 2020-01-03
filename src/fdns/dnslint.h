#ifndef DNS_LINT_H
#define DNS_LINT_H

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

typedef struct __attribute__((__packed__)) dns_question_t {
// maximum domain name including the first label length byte and terminating '\0'
#define DNS_MAX_DOMAIN_NAME 255
	char domain[DNS_MAX_DOMAIN_NAME];
	uint16_t type;	// RR type requested
	unsigned len;	// question length
	unsigned dlen;	// domain name length (len - 6)
} DnsQuestion;

// error checking
#define DNSERR_OK 0
#define DNSERR_INVALID_HEADER 1
#define DNSERR_INVALID_DOMAIN 2
#define DNSERR_INVALID_CLASS 3
#define DNSERR_MAX 4		// always the last one
int dnslint_error(void);
const char *dnslint_err2str(void);

DnsHeader *dnslint_header(uint8_t *pkt, unsigned len, unsigned *size);
DnsQuestion *dnslint_question(uint8_t *pkt, unsigned len, unsigned *size);

#endif
