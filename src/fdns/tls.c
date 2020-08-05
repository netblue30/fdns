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

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include "fdns.h"
#include "timetrace.h"

static void tls_header_stats(void);
static double tls_bandwidth(void);
static void tls_init(void);
static void tls_close(void);
static int tls_connect(void);
static int tls_send_exampledotcom(uint8_t *req);
static int tls_send_query(uint8_t *req, int cnt);
static int tls_send_ping(void);
static int tls_exchange(uint8_t *response, uint32_t stream);
DnsTransport tls_transport = {
	"tls",
	"DoT",
	tls_init,
	tls_close,
	tls_connect,
	tls_send_exampledotcom,
	tls_send_query,
	tls_send_ping,
	tls_exchange,
	tls_header_stats,
	tls_bandwidth
};


static int tls_rx = 0; // received bytes, including IP/TCP/TLS headers
static int tls_rx_dns = 0; // received DNS bytes over H2 plus IP/UDP
static int first_query = 1;	// don't include the first query in network byte count

static void tls_header_stats(void) {
}

// Do53 / DoH ratio
static double tls_bandwidth(void) {
	if (tls_rx_dns == 0)
		return 0;
	return (double) tls_rx / (double) tls_rx_dns;
}

static void tls_init(void) {
	first_query = 1;
}

static void tls_close(void) {
	first_query = 1;
}

static uint8_t buf_query[MAXBUF];
// returns -1 if error
static int tls_connect(void) {
	return 0;
}

// the result message is placed in res, the length of the message is returned
// returns -1 if error
static int tls_send_exampledotcom(uint8_t *req) {
#if 0
	uint8_t dnsmsg[] = {
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f,
		0x6d, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00
//		, 0x00, 0x00, 0x29 (OPT record), 0x10, 0x00 (UDP payload), 0x00 (Higher bits), 0x00 (EDNS version),
//		 0x00, 0x00 (Z), 0x00, 0x08 (length),
//                                      0x00, 0x08 (code), 0x00, 0x04 (length), 0x00, 0x01 (family), 0x00 (source prefix-len), 0x00 (scope prefix-len)
	};
#endif
	uint8_t dnsmsg[] = {
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f,
		0x6d, 0x00, 0x00, 0x02, 0x00, 0x01
	};

	// two bytes length field
	uint16_t len = htons(sizeof(dnsmsg));
	memcpy(buf_query, &len, 2);
	memcpy(buf_query + 2, dnsmsg, sizeof(dnsmsg));

	if (arg_debug || arg_debug_transport) {
		print_time();
		printf("(%d) tx len %d tls\n", arg_id, (int) sizeof(dnsmsg) + 2);
	}
	ssl_tx(buf_query, sizeof(dnsmsg) + 2);
	int rv = tls_exchange(req, 0);
	first_query = 0;
	return rv;
}


// the result message is placed in req, the length of the message is returned
// returns -1 if error
static int tls_send_query(uint8_t *req, int cnt) {
	// two bytes length field
	uint16_t len = htons(cnt);
	memcpy(buf_query, &len, 2);
	memcpy(buf_query + 2, req, cnt);

	if (arg_debug || arg_debug_transport) {
		print_time();
		printf("(%d) tx len %d tls\n", arg_id, cnt + 2);
	}
	ssl_tx(buf_query, cnt + 2);
	int rv = tls_exchange(req, 0);
	first_query = 0;
	return rv;
}

// returns -1 if error
static int tls_send_ping(void) {
	return tls_send_exampledotcom(buf_query);
}

// copy rx data in response and return the length
// return -1 if error
static int tls_exchange(uint8_t *response, uint32_t stream) {
	assert(response);
	(void) stream;

	uint8_t buf[MAXBUF];
	int total_len = ssl_rx_timeout((uint8_t *) buf, TLS_TIMEOUT);
	if (total_len == 0)
		goto errout;

	if (arg_debug)
		print_mem(buf, total_len);

	if (arg_debug || arg_debug_transport) {
		print_time();
		printf("(%d) rx len %d tls\n", arg_id, total_len);
	}

	tls_rx += 20 + 20 + 5 +  (int) ((float) total_len * 1.2); // ip + tcp + tls

	uint16_t len;
	memcpy(&len, buf, 2);
	len = ntohs(len);
	if (len > (MAXBUF - 2))
		goto errout;

	if ((arg_debug || arg_details) && first_query) {
		printf("\n   Network trace:\n");
		printf("-----> rx %d bytes: IP + TCP + TLS\n", 20 + 20 + 5 + (int) ((float) total_len * 1.2));
	}

	if ((total_len - 2) > len) {
		// read some more data
		int newlen = ssl_rx_timeout(buf + total_len, TLS_TIMEOUT);
		if (len == 0)
			goto errout;
		if (arg_debug || arg_debug_transport) {
			print_time();
			printf("(%d) rx len %d tls\n", arg_id, total_len);
		}
		total_len += newlen;
		tls_rx += 20 + 20 + 5 + (int) ((float) newlen * 1.2); // ip + tcp + tls
		if ((arg_debug || arg_details) && first_query)
			printf("-----> rx %d bytes: IP + TCP + TLS\n", 20 + 20 + 5 + (int) ((float) newlen * 1.2));
	}
	if ((arg_debug || arg_details) && first_query)
		printf("\n");

	// bailout!
	if ((total_len - 2) > len)
		goto errout;

	if (arg_debug)
		print_mem(buf + 2, len);

	tls_rx_dns += 20 + 8 + len; // ip + tcp + tls + dns

	// copy response in buf_query_data
	if (len != 0) {
		memcpy(response, buf + 2, len);
		return len;
	}


errout:
	if (arg_id > 0)
		rlogprintf("Error: tls timeout\n");
	else
		fprintf(stderr, "Error: tls timeout\n");
	fflush(0);
	if (ssl_state == SSL_OPEN)
		ssl_close();
	return -1;
}



