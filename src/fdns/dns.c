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
#include "timetrace.h"

static int print_stats = 0;
static uint8_t rbuf[MAXBUF];
static ssize_t rbuf_len;


// redirect to 127.0.0.1
// packet format: response_loopback1 + question + response_loopback2
static uint8_t response_loopback1[] = {
// ID
	0, 0,
// Flags
	0x81, 0x80,
// Questions etc.
	0, 1, 0, 1, 0, 0, 0, 0
};

static uint8_t response_loopback2[] = {
	0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0xaa, 0xaa, 0, 4, 0x7f, 0, 0, 1
};

static void  build_response_loopback(uint8_t id0, uint8_t id1, uint8_t *question, int qlen) {
	// header
	memcpy(rbuf, response_loopback1, sizeof(response_loopback1));
	rbuf[0] = id0;
	rbuf[1] = id1;

	// question
	memcpy(rbuf + sizeof(response_loopback1), question, qlen);

	//response
	memcpy(rbuf + sizeof(response_loopback1) + qlen, response_loopback2, sizeof(response_loopback2));
	rbuf_len = sizeof(response_loopback1) + qlen + sizeof(response_loopback2);
}


// NXDOMAIN
// packet format: response_nxdomain + question
static uint8_t response_nxdomain[] = {
// ID
	0, 0,
// Flags
	0x81, 0x83,	// NXDOMAIN
//	0x81, 0x80,	// <-- NO DATA RESPONSE TYPE 3, RFC2308
// Questions etc.
	0, 1, 0, 0, 0, 0, 0, 0
};

static void  build_response_nxdomain(uint8_t id0, uint8_t id1, uint8_t *question, int qlen) {
	// header
	memcpy(rbuf, response_nxdomain, sizeof(response_nxdomain));
	rbuf[0] = id0;
	rbuf[1] = id1;

	// question
	memcpy(rbuf + sizeof(response_nxdomain), question, qlen);

	rbuf_len = sizeof(response_nxdomain) + qlen;
}

// attempt to extract the domain name and run it through the filter
uint8_t *dns_parser(uint8_t *buf, ssize_t *lenptr) {
	assert(buf);
	assert(lenptr);

	//*****************************
	// parse DNS query
	//*****************************
	ssize_t len = *lenptr;
	char output[len];
	memcpy(output, buf, len);

#define QOFFSET 12
	// check a minimum length of the request
	// - an empty request with a 2 byte type and a 2 byte class
	if (len < QOFFSET + 1 + 4)
		return NULL; // allow

// ID - 2 bytes
	uint16_t id;
	memcpy(&id, buf, 2);
	id = htons(id);

// Flags - 2 bytes
	// we don't really care about flags

// Questions - 2 bytes
	// we only look for a single question - is not worth trying to parse multiple questions requests
	if (*(buf + 4) != 0 || *(buf + 5) != 1)
		return NULL; // allow

// Answers - 2 bytes
	// there should be no answer in this request!
	if (*(buf + 6) != 0 || *(buf + 7) != 0)
		return NULL; // allow

// Autohority RRs - 2
// Additional RRS - 2
	if (*(buf + 8) != 0 ||  *(buf + 9) != 0 || *(buf + 10) != 0 ||  *(buf + 11) != 0)
		return NULL; // allow

// Query - offset 12 - see QOFFSET definition above
	char *ptr = output + QOFFSET;
	int position = QOFFSET;
	while (1) {
		uint8_t sz = *ptr;
		// sz should be smaller than 63
		// domain compression is not supported
		if (sz > 63)
			return NULL; // allow

		if (position + sz >= len || sz == 0) {
			*ptr = '\0';
			break;
		}
		*ptr = '.';
		ptr += sz + 1;
		position += sz + 1;
	}

	// in this moment we are positioned at the end of the host name; it should be a \0 here
	if (*ptr != 0)
		return NULL; // allow

	// domain name length 255; this includes the first length filed and the ending \0
	if ((position - QOFFSET) > 253)
		return NULL; // allow


	// there shouldn't be anything else in the packet
	if (len != position + 1 + 4 )
		return NULL; //allow
	ptr++;

	// clear cache name
	cache_set_name("", 0);

	//******************************
	// query type
	//******************************
	int aaaa = 0;

	// drop ANY by default - RFC8482
	if (*ptr == 0 && *(ptr + 1) == 255 && *(ptr + 2) == 0 && *(ptr + 3) == 1)
		goto drop_nxdomain;

	// check querry filtering configuration
	if (arg_allow_all_queries == 0) {
		// type A requests
		if (*ptr == 0 && *(ptr + 1) == 1 && *(ptr + 2) == 0 && *(ptr + 3) == 1);

		// AAAA requests
		else if (*ptr == 0 && *(ptr + 1) == 0x1c && *(ptr + 2) == 0 && *(ptr + 3) == 1) {
			aaaa = 1;
			if (!arg_ipv6) {
				rlogprintf("Request: %s (ipv6), dropped\n", output + QOFFSET + 1);
				goto drop_nxdomain;
			}
		}

		// drop all the rest and respond with NXDOMAIN
		else {
			rlogprintf("Request: type %02x %02x class %02x %02x rejected\n", *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3));
			goto drop_nxdomain;
		}
	}


	//*****************************
	// trackers/adblock filtering
	//*****************************
	if (arg_nofilter) {
		rlogprintf("Request: %s\n", output + QOFFSET + 1);
		return NULL;
	}

	int rv = dnsfilter_blocked(output + QOFFSET + 1, 0);
	if (rv) {
		rlogprintf("Request: %s%s, dropped\n", output + QOFFSET + 1, (aaaa)? " (ipv6)": "");
		stats.drop++;
		build_response_loopback(*buf, *(buf + 1), buf + QOFFSET, strlen(output + QOFFSET + 1) + 1 + 5);
		*lenptr = rbuf_len;
		print_stats = 1;
		return rbuf;
	}
	else {
		// check cache
		uint8_t *rv = cache_check(*buf, *(buf + 1), output + QOFFSET + 1, lenptr, aaaa);
		if (rv) {
			stats.cached++;
			rlogprintf("Request: %s%s, cached\n", output + QOFFSET + 1, (aaaa)? " (ipv6)": "");
			return rv;
		}

		// set the stage for caching the reply
		cache_set_name(output + QOFFSET + 1, aaaa);
		rlogprintf("Request: %s%s, %s\n", output + QOFFSET + 1, (aaaa)? " (ipv6)": "",
			(ssl_state == SSL_OPEN)? "encrypted": "not encrypted");
		return NULL;
	}

	return NULL;

drop_nxdomain:
	stats.drop++;
	build_response_nxdomain(*buf, *(buf + 1), buf + QOFFSET, strlen(output + QOFFSET + 1) + 1 + 5);
	*lenptr = rbuf_len;
	print_stats = 1;
	return rbuf;
}


