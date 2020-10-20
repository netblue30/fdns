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
#include "lint.h"

static void h11_header_stats(void);
static double h11_bandwidth(void);
static void h11_init(void);
static void h11_close(void);
static int h11_connect(void);
static int h11_send_exampledotcom(uint8_t *req);
static int h11_send_query(uint8_t *req, int cnt);
static int h11_send_ping(void);
static int h11_exchange(uint8_t *response, uint32_t stream);
static void h11_print_url(void);
DnsTransport h11_transport = {
	"http/1.1",
	"DoH",
	h11_init,
	h11_close,
	h11_connect,
	h11_send_exampledotcom,
	h11_send_query,
	h11_send_ping,
	h11_exchange,
	h11_header_stats,
	h11_bandwidth,
	h11_print_url
};


static unsigned h11_header_total_len = 0;	// accumulated header length
static int h11_header_cnt = 0;		// counting number of headers frames
static int h11_rx = 0; // received bytes, including IP/TCP/TLS headers
static int h11_rx_dns = 0; // received DNS bytes over H2 plus IP/UDP


static int first_query = 1;	// don't include the first query in network byte count


static void h11_print_url(void) {
	DnsServer *srv = server_get();
	assert(srv);
	printf("   URL: https://%s%s\n", srv->host, srv->path);
}

static void h11_header_stats(void) {
	if (h11_header_cnt == 0)
		return;
	printf("   Header size: %d bytes\n",
		h11_header_total_len / h11_header_cnt);
}

// Do53 / DoH ratio
static double h11_bandwidth(void) {
	if (h11_rx_dns == 0)
		return 0;
	return (double) h11_rx / (double) h11_rx_dns;
}

static void h11_init(void) {
//	first_header_sent = 0;
//	first_query = 1;
//	second_query = 0;
}

static void h11_close(void) {
//	first_header_sent = 0;
//	first_query = 1;
//	second_query = 0;
}



static uint8_t buf_query[MAXBUF];
// returns -1 if error
static int h11_connect(void) {
	return 0;
}

static char *push_request_tail =
	"Accept: application/dns-message\r\n" \
	"Content-Type: application/dns-message\r\n" \
	"Content-Length: %d\r\n" \
	"\r\n";

// the result message is placed in res, the length of the message is returned
// returns -1 if error
static int h11_send_exampledotcom(uint8_t *req) {
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

	DnsServer *s = server_get();
	sprintf((char *) buf_query, "POST %s HTTP/1.1\r\nHost: %s\r\n",  s->path, s->host);
	uint8_t *ptr = buf_query + strlen((char *) buf_query);
	sprintf((char *) ptr, push_request_tail, sizeof(dnsmsg));
	ptr += strlen((char *) ptr);
	memcpy(ptr, dnsmsg, sizeof(dnsmsg));
	ptr += sizeof(dnsmsg);

	ptrdiff_t len = ptr - buf_query;
	if (arg_debug || arg_debug_transport) {
		print_time();
		printf("(%d) tx len %d http/1.1 POST\n", arg_id, (int) len);
	}

	ssl_tx(buf_query, len);

	int rv = h11_exchange(req, 0);
	first_query = 0;
	return rv;
}


// the result message is placed in req, the length of the message is returned
// returns -1 if error
static int h11_send_query(uint8_t *req, int cnt) {
	if (cnt <= 0 || cnt > DNS_MAX_DOMAIN_NAME)
		return 0;

	DnsServer *s = server_get();
	sprintf((char *) buf_query, "POST %s HTTP/1.1\r\nHost: %s\r\n",  s->path, s->host);
	uint8_t *ptr = buf_query + strlen((char *) buf_query);
	sprintf((char *) ptr, push_request_tail, cnt);
	ptr += strlen((char *) ptr);
	memcpy(ptr, req, cnt);
	ptr += cnt;

	ptrdiff_t len = (uint8_t *) ptr - buf_query;
	if (arg_debug || arg_debug_transport) {
		print_time();
		printf("(%d) tx len %d http/1.1 POST\n", arg_id, (int) len);
	}

	ssl_tx(buf_query, len);

	int rv = h11_exchange(req, 0);
	first_query = 0;
	return rv;
}

// returns -1 if error
static int h11_send_ping(void) {
	return h11_send_exampledotcom(buf_query);
}

static void print_header(const char *str) {
	char *buf = strdup(str);
	if (!buf)
		errExit("strdup");
	printf("\n   HTTP Header\n");
	printf("-----------------------------\n");
	char *ptr = strtok(buf, "\n");
	while (ptr) {
		printf("|  %s\n", ptr);
		ptr = strtok(NULL, "\n");
	}
	printf("-----------------------------\n");
	free(buf);
}

// copy rx data in response and return the length
// return -1 if error
static int h11_exchange(uint8_t *response, uint32_t stream) {
	assert(response);
	(void) stream;

	char buf[MAXBUF];
	int total_len = ssl_rx_timeout((uint8_t *) buf, MAXBUF, H11_TIMEOUT);
	if (total_len == 0)
		goto errout;

	if (arg_debug)
		print_mem(buf, total_len);
	if (arg_debug || arg_debug_transport) {
		print_time();
		printf("(%d) rx len %d http/1.1 200 OK\n", arg_id, total_len);
	}

	h11_rx += 20 + 20 + 5 +  (int) ((float) total_len * 1.2); // ip + tcp + tls + http/1.1

	// check 200 OK
	char *ptr = strstr(buf, "200 OK");
	if (!ptr) {
		buf[16] = '\0';
		rlogprintf("Warning: HTTP/1.1 error: %s\n", buf);
		goto errout;
	}

	// look for the end of http header
	ptr = strstr(buf, "\r\n\r\n");
	if (!ptr) {
		rlogprintf("Warning: cannot parse HTTP/1.1 response, didn't recieve a full http header\n");
		goto errout;
	}
	ptr += 4; // length of "\r\n\r\n"
	ptrdiff_t hlen = ptr - buf;

	h11_header_total_len += hlen;
	h11_header_cnt++;
	*(ptr - 1) = 0;
	if ((arg_debug || arg_details) && first_query) {
		print_header(buf);
		printf("\n   Network trace:\n");
		printf("-----> rx %d bytes: IP + TCP + TLS + HTTP/1.1\n", 20 + 20 + 5 + (int) ((float) total_len * 1.2));
	}

	// look for Content-Length:
	char *contlen = "Content-Length: ";
	ptr = strcasestr(buf, contlen);
	int datalen = 0;
	if (!ptr) {
		rlogprintf("Warning: cannot parse HTTPS response, content-length missing\n");
		goto errout;
	}
	else {
		ptr += strlen(contlen);
		sscanf(ptr, "%d", &datalen);
		if (datalen == 0) // we got a "Content-lenght: 0"; this is probably a HTTP error
			return 0;
	}

	// give it another chance
	if ((hlen + datalen) > total_len) {
		int len = ssl_rx_timeout((uint8_t *) buf + hlen, MAXBUF - hlen, H11_TIMEOUT);
		if (len == 0)
			goto errout;
		total_len += len;
		h11_rx += 20 + 20 + 5 + (int) ((float) len * 1.2); // ip + tcp + tls + http/1.1
		if ((arg_debug || arg_details) && first_query)
			printf("-----> rx %d bytes: IP + TCP + TLS + HTTP/1.1\n", 20 + 20 + 5 + (int) ((float) len * 1.2));
		if (arg_debug || arg_debug_transport) {
			print_time();
			printf("(%d) rx len %d http/1.1 200 OK (cont)\n", arg_id, len);
		}
	}
	if ((arg_debug || arg_details) && first_query)
		printf("\n");

	// bailout!
	if ((hlen + datalen) > total_len)
		goto errout;

	ptr = buf + hlen;
	if (arg_debug)
		print_mem(ptr, datalen);

	h11_rx_dns += 20 + 8 + datalen; // ip + udp + dns
	// copy response in buf_query_data
	if (datalen != 0) {
		memcpy(response, ptr, datalen);
		return datalen;
	}


errout:
	if (arg_id > 0)
		rlogprintf("Error: http/1.1 timeout\n");
	else
		fprintf(stderr, "Error: http/1.1 timeout\n");
	fflush(0);
	if (ssl_state == SSL_OPEN)
		ssl_close();
	return -1;
}



