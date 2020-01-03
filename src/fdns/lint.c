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
#include "lint.h"

//***********************************************
// error
//***********************************************
static int dnserror;
static const char *err2str[DNSERR_MAX] = {
	"no error",
	"invalid header",
	"invalid domain",
	"invalid class"
};

int lint_error(void) {
	return dnserror;
}

const char *lint_err2str(void) {
	assert(dnserror < DNSERR_MAX);
	return err2str[dnserror];
}

//***********************************************
// lint
//***********************************************
static DnsHeader hdr;
static DnsQuestion question;

// check chars in domain name: a-z, A-Z, and 0-9
// return 0 if ok, 1 if bad
//TODO: add support or IDNA and/or Punycode (rfc3492)
static inline int check_char(const uint8_t c)  {
	if (c >= 'a' && c <= 'z')
		return 0;
	else if (c >= 'A' && c <= 'Z')
		return 0;
	else if ( c>= '0' && c <= '9')
		return 0;
	else if (c =='-')
		return 0;

	return 1;
}

// parse a domain name
// error if cross-references
// size - number of packet bytes consumed
// return -1 if error, 0 if ok
static int domain_size_no_crossreference(const uint8_t *data, char *domain_name, unsigned *size){
	assert(data);
	assert(domain_name);
	assert(size);
	unsigned i = 0;
	unsigned chunk_size = *data;

	// skip each set of chars until (0) at the end
	while(chunk_size != 0){
		if (chunk_size > 63)
			goto errexit;
		i += chunk_size + 1;
		if (i > 255)
			goto errexit;

		// check chars in domain name
		const uint8_t *ptr = data + i - chunk_size - 1 + 1;
		unsigned j;
		for (j = 0; j < chunk_size; j++, ptr++) {
//printf("%02x - %c\n", *ptr, (char) *ptr);
			if (check_char(*ptr))
				goto errexit;
		}

		memcpy(domain_name + i - chunk_size - 1, data + i - chunk_size -1 + 1, chunk_size);
		domain_name[i - 1] = '.';
		chunk_size = data[i];
	}

	// domain name including the ending \0
	domain_name[i - 1] = '\0';
	*size = i + 1;
	return 0;
errexit:
	dnserror = DNSERR_INVALID_DOMAIN;
	return -1;
}

// pkt - start of the dns packet
// size - packet bytes consumed durring the parsing
DnsHeader *lint_header(uint8_t *pkt, unsigned len, unsigned *size) {
	assert(pkt);

	*size = 0;
	if (len < sizeof(DnsHeader)) {
		dnserror = DNSERR_INVALID_HEADER;
		return NULL;
	}

	memcpy(&hdr, pkt, sizeof(hdr));
	hdr.id = ntohs(hdr.id);
	hdr.flags = ntohs(hdr.flags);
	hdr.questions = ntohs(hdr.questions);
	hdr.answer = ntohs(hdr.answer);
	hdr.authority = ntohs(hdr.authority);
	hdr.additional = ntohs(hdr.additional);
	*size = sizeof(DnsHeader);
	return &hdr;
}

// pkt is positioned at the the start of RR
DnsQuestion *lint_question(uint8_t *pkt, unsigned len, unsigned *size) {
	assert(pkt);
	if (len < 1 + 2 + 2) { // empty domain + type + class
		dnserror = DNSERR_INVALID_DOMAIN;
		return NULL;
	}

	// clanup
	question.domain[0] = '\0';
	question.type = 0;
	*size = 0;

	// first byte smaller than 63
	if (*pkt > 63) {
		dnserror = DNSERR_INVALID_DOMAIN;
		return NULL;
	}
	if (domain_size_no_crossreference(pkt, question.domain, size)) {
		dnserror = DNSERR_INVALID_DOMAIN;
		return NULL;
	}

	// check length
	if (*size + 4 > len) {
		dnserror = DNSERR_INVALID_DOMAIN;
		return NULL;
	}

	// set type
	pkt += *size;
	memcpy(&question.type, pkt, 2);
	question.type = ntohs(question.type);
	pkt += 2;

	// check class
	uint16_t cls;
	memcpy(&cls, pkt,  2);
	cls = ntohs(cls);
	if (cls != 1) {
		dnserror = DNSERR_INVALID_CLASS;
		return NULL;
	}

	*size += 4;
	question.len = *size;
	question.dlen = question.len - 6; // we are assuming a domain name without crossreferences
//printf("len/size %d/%d\n", len, *size);
	return &question;
}
