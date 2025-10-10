/*
 * Copyright (C) 2019-2021 FDNS Authors
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
#include "fdns.h"
#include "timetrace.h"

//***********************************************
// error
//***********************************************
static int dnserror;
static uint8_t dnserror_ipv4[4];
static char dnserror_str[50];
static const char *err2str[DNSERR_MAX] = {
	"no error",
	"invalid header length",
	"invalid header QR flag",
	"invalid domain",
	"invalid class",
	"nxdomain",
	"multiple questions",
	"invalid packet length",
	"invalid RR length",
	"potential rebinding attack",
	"cname cloaking",
	"invalid cname"
};

int lint_error(void) {
	return dnserror;
}

const char *lint_err2str(void) {
	assert(dnserror < DNSERR_MAX);

	if (dnserror == DNSERR_REBINDING_ATTACK) {
		sprintf(dnserror_str, "%s %u.%u.%u.%u",
			err2str[dnserror],
			(unsigned) dnserror_ipv4[0],
			(unsigned) dnserror_ipv4[1],
			(unsigned) dnserror_ipv4[2],
			(unsigned) dnserror_ipv4[3]);
		return dnserror_str;
	}

	return err2str[dnserror];
}

//***********************************************
// cname reporting
//***********************************************
static uint8_t cname[256 + 1];
// get last cname
const char *lint_get_cname(void) {
	return (const char *) cname + 1;
}
//***********************************************
// lint
//***********************************************
static DnsHeader hdr;
static DnsQuestion question = {"\0", 0, 0, 0};

// check chars in domain name: a-z, A-Z, and 0-9
// return 0 if ok, 1 if bad
//TODO: add support or IDNA and/or Punycode (rfc3492)
static inline int check_char(const uint8_t c)  {
	if (c >= 'a' && c <= 'z')
		return 0;
	else if (c >= 'A' && c <= 'Z')
		return 0;
	else if ( c >= '0' && c <= '9')
		return 0;
	else if (c == '-')
		return 0;

	return 1;
}

// parse a domain name
// error if cross-references
// size - number of packet bytes consumed
// return -1 if error, 0 if ok
static int domain_size_no_crossreference(const uint8_t *data, char *domain_name, unsigned *size) {
	assert(data);
	assert(domain_name);
	assert(size);
	unsigned i = 0;
	unsigned chunk_size = *data;

	// skip each set of chars until (0) at the end
	while(chunk_size != 0) {
		if (chunk_size > 63)
			goto errexit;
		i += chunk_size + 1;
		if (i > DNS_MAX_DOMAIN_NAME)
			goto errexit;

		// check chars in domain name
		const uint8_t *ptr = data + i - chunk_size - 1 + 1;
		unsigned j;
		for (j = 0; j < chunk_size; j++, ptr++) {
//printf("%02x - %c\n", *ptr, (char) *ptr);
			if (check_char(*ptr))
				goto errexit;
		}

		memcpy(domain_name + i - chunk_size - 1, data + i - chunk_size - 1 + 1, chunk_size);
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

// return 1 if we have a compressed domain
static uint16_t clean_domain(uint8_t *ptr, unsigned len) {
	assert(ptr);
	uint8_t *end = ptr + len;
	uint16_t rv = 0;

	while (*ptr != 0 && ptr < end) {
		if ((*ptr & 0xc0) == 0) {
			uint8_t jump = *ptr + 1;
			*ptr = '.';
			ptr += jump;
		}
		else {
			rv = ((*ptr) ^ 0xc0) * 256 + *(ptr + 1);
			break;
		}

	}

	return rv;
}

// return -1 if error, 0 if ok
static int skip_name(uint8_t **pkt, uint8_t *last) {
	dnserror = DNSERR_OK;

	if (*pkt > last) {
		dnserror = DNSERR_INVALID_PKT_LEN;
		return -1;
	}

	while (**pkt != 0 && *pkt < (last - 1)) {
		if ((**pkt & 0xc0) == 0)
			*pkt +=  **pkt + 1;
		else {
			(*pkt)++;
			break;
		}
	}
	(*pkt)++;
	return 0;
}

// return -1 if error, 0 if ok
static inline int check_ipv4(uint8_t *ptr) {
	uint32_t ip;
	memcpy(&ip, ptr, 4);
	ip = ntohl(ip);

	// RFC 5735 section 4
	if ((ip & 0xff000000) == 0 ||		// 0.0.0.0/8           "This" Network 	RFC 1122, Section 3.2.1.3
	     (ip & 0xff000000) == 0x0a000000 ||	// 10.0.0.0/8          Private-Use Networks 	RFC 1918
	     (ip & 0xff000000) == 0x7f000000 ||	// 127.0.0.0/8         Loopback  	RFC 1122, Section 3.2.1.3
	     (ip & 0xffff0000) == 0xa9fe0000 ||	// 169.254.0.0/16      Link Local  	RFC 3927
	     (ip & 0xfff00000) == 0xac100000 ||	// 172.16.0.0/12       Private-Use Networks 	RFC 1918

//	     (ip & 0xffffff00) == 0xc0000000 ||	// 192.0.0.0/24        IETF Protocol Assignments 	RFC 5736
// RFC8880 - ipv4only.arpa: 192.0.0.170, 192.0.0.171 - used to detect DNS64 middle boxes

	     (ip & 0xffffff00) == 0xc0000200 ||	// 192.0.2.0/24        TEST-NET-1 	RFC 5737
	     (ip & 0xffffff00) == 0xc0586300 ||	// 192.88.99.0/24      6to4 Relay Anycast         RFC 3068
	     (ip & 0xffff0000) == 0xc0a80000 ||	// 192.168.0.0/16      Private-Use Networks       RFC 1918
	     (ip & 0xfffe0000) == 0xc6120000 ||	// 198.18.0.0/15       Network Interconnect Device Benchmark Testing   RFC 2544
	     (ip & 0xffffff00) == 0xc6336400 ||	// 198.51.100.0/24     TEST-NET-2                 RFC 5737
	     (ip & 0xffffff00) == 0xcb007100 ||	// 203.0.113.0/24      TEST-NET-3                 RFC 5737
	     (ip & 0xf0000000) == 0xe0000000 ||	// 224.0.0.0/4         Multicast                  RFC 3171
	     (ip & 0xf0000000) == 0xf0000000 ||	// 240.0.0.0/4         Reserved for Future Use    RFC 1112, Section 4
	     (ip & 0xffffffff) == 0xffffffff)		// 255.255.255.255/32  Limited Broadcast

		return -1;

	return 0;
}

//***********************************************
// public interface
//***********************************************
// pkt positioned at start of packet
DnsHeader *lint_header(uint8_t **pkt, uint8_t *last) {
	assert(pkt);
	assert(*pkt);
	assert(last);
	dnserror = DNSERR_OK;

	if (*pkt + sizeof(DnsHeader) > last) {
		dnserror = DNSERR_INVALID_HEADER_LENGTH;
		return NULL;
	}

	memcpy(&hdr, *pkt, sizeof(hdr));
	hdr.id = ntohs(hdr.id);
	hdr.flags = ntohs(hdr.flags);
	hdr.questions = ntohs(hdr.questions);
	hdr.answer = ntohs(hdr.answer);
	hdr.authority = ntohs(hdr.authority);
	hdr.additional = ntohs(hdr.additional);
	*pkt += sizeof(DnsHeader);
	return &hdr;
}

// pkt positioned at the the start of question
DnsQuestion *lint_question(uint8_t **pkt, uint8_t *last) {
	assert(pkt);
	assert(*pkt);
	assert(last);
	dnserror = DNSERR_OK;

	if (*pkt + 1 + 2 + 2 > last) { // empty domain + type + class
		dnserror = DNSERR_INVALID_DOMAIN;
		return NULL;
	}

	// clanup
	question.domain[0] = '\0';
	question.type = 0;
	unsigned size = 0;

	// first byte smaller than 63
	if (**pkt > 63) {
		dnserror = DNSERR_INVALID_DOMAIN;
		return NULL;
	}

	if (domain_size_no_crossreference(*pkt, question.domain, &size)) {
		dnserror = DNSERR_INVALID_DOMAIN;
		return NULL;
	}

	// check length
	if (*pkt + size + 4 - 1 > last ) {
		dnserror = DNSERR_INVALID_DOMAIN;
		return NULL;
	}

	// set type
	*pkt += size;
	memcpy(&question.type, *pkt, 2);
	question.type = ntohs(question.type);
	*pkt += 2;

	// check class
	uint16_t cls;
	memcpy(&cls, *pkt,  2);
	cls = ntohs(cls);
	if (cls != 1) {
		dnserror = DNSERR_INVALID_CLASS;
		return NULL;
	}
	*pkt += 2;

	question.len = size + 4;
	question.dlen = question.len - 6; // we are assuming a domain name without cross-references
	return &question;
}


// return -1 if error, 0 if fine
// pkt positioned at start of packet
int lint_rx(uint8_t *pkt, unsigned len) {
	assert(pkt);
	assert(len);
	uint8_t *last = pkt + len - 1;
	dnserror = DNSERR_OK;
	uint8_t *pktstart = pkt;

	// check header
	DnsHeader *h = lint_header(&pkt, last);
	if (!h)
		return -1;

	// check response field
	if ((h->flags & 0x8000) == 0) {
		dnserror = DNSERR_INVALID_HEADER_QR;
		return -1;
	}
	// check errors such as NXDOMAIN -> caching the response for a very short time
	if ((h->flags & 0x000f) != 0) {
		dnserror = DNSERR_NXDOMAIN;
		return -1;
	}

	// one single question
	if (h->questions != 1) {
		dnserror = DNSERR_MULTIPLE_QUESTIONS;
		return -1;
	}
	if (skip_name(&pkt, last))
		return -1;
	pkt += 2;
	if (pkt > last) {
		dnserror = DNSERR_INVALID_PKT_LEN;
		return -1;
	}

	// invalid class
	uint16_t cls;
	memcpy(&cls, pkt, 2);
	cls = ntohs(cls);
	if (cls != 1) {
		dnserror = DNSERR_INVALID_CLASS;
		return -1;
	}
	pkt += 2;
	if (pkt > last) {
		dnserror = DNSERR_INVALID_PKT_LEN;
		return -1;
	}

	// extract CNAMEs from the answer section
	int i;
	for (i = 0; i < h->answer; i++) {
		if (skip_name(&pkt, last))
			return -1;

		// extract record
		if (pkt + sizeof(DnsRR) > last) {
			dnserror = DNSERR_INVALID_PKT_LEN;
			return -1;
		}
		DnsRR rr;
		memcpy(&rr, pkt, sizeof(DnsRR));
		rr.type = ntohs(rr.type);
		rr.cls = ntohs(rr.cls);
		rr.ttl = ntohl(rr.ttl);
		rr.rlen = ntohs(rr.rlen);
		// replace ttl with 600
		*(pkt + 4) = 0;
		*(pkt + 5) = 0;
		*(pkt + 6) = 2;
		*(pkt + 7) = 0x58;

		pkt += sizeof(DnsRR);

		if (pkt + rr.rlen > (last + 1)) {
			dnserror = DNSERR_INVALID_PKT_LEN;
			return -1;
		}

		if (arg_debug) {
			print_time();
			printf("type %u, class %u, ttl %u, rlen %u\n",
			       rr.type, rr.cls, rr.ttl, rr.rlen);
		}
		
		if (rr.type == 1) { // A
			if (rr.rlen != 4) {
				dnserror = DNSERR_INVALID_RLEN;
				return -1;
			}

			if (check_ipv4(pkt)) {
				dnserror = DNSERR_REBINDING_ATTACK;
				memcpy(dnserror_ipv4, pkt, 4);
				return -1;
			}
			if (arg_debug) {
				print_time();
				printf("(%d) %s %u.%u.%u.%u\n", arg_id, cache_get_name(), *pkt, *(pkt + 1), *(pkt + 2), *(pkt +3));
			}
		}
		else if (rr.type == 5) { // CNAME
			// CNAME Cloaking is implemented partially
			if (rr.rlen > 253) {
				dnserror = DNSERR_INVALID_RLEN;
				return -1;
			}

			memset(cname, 0, sizeof(cname));
			memcpy(cname, pkt, rr.rlen);
			cname[rr.rlen] = '\0';

			// clean cname
			uint16_t rv = clean_domain(cname, rr.rlen);
			if (rv) { // compressed domain
				// check length
				unsigned len = *(pktstart + rv);
				if ((rr.rlen + len) > sizeof(cname)) {
					dnserror = DNSERR_INVALID_CNAME;
					return -1;
				}

				// copy
				cname[rr.rlen - 2] = '.';
				memcpy(cname + rr.rlen - 1, pktstart + rv + 1, len);
				cname[rr.rlen + len - 1] = '\0';
				if (cname[rr.rlen + len - 1 - 2] & 0xc0)
					rv = 1;
				else
					rv = 0;
			}

			if (arg_debug) {
				print_time();
				printf("(%d) ", arg_id);
				printf("CNAME: %s\n", cname + 1);
				fflush(0);
			}

			// CNAME Cloaking Blocklist
			if (!arg_nofilter && !rv && filter_blocked((char *) cname + 1, 0, 1)) {
				dnserror = DNSERR_CNAME_CLOAKING;
				return -1;
			}
		}
		else if (rr.type ==0x1c) {
			if (rr.rlen != 28) {
				dnserror = DNSERR_INVALID_RLEN;
				return -1;
			}
			// todo: check ipv6 address
		}
		pkt += rr.rlen;
	}

	return 0;
}
