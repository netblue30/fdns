// gcc -lhpack -o cashbld cashbld.c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>

#include "h2frame.h"
#include "hpack_static.h"
#include "fdns.h"


static unsigned long long h2_header_total = 0;
static int h2_header_cnt = 0;	// skip the first header
static int h2_first_header_len = 0;
static uint32_t stream_id;
static int printing = 0; // used to print server: header field for --test-server option


// average length of the
int h2_header_average(void) {
	return (h2_header_cnt <= 0)? 0: (int) (h2_header_total / (unsigned long long) h2_header_cnt);
}

int h2_first_header(void) {
	return h2_first_header_len;
}


static int first_header_sent = 0;
void h2_init(void) {
	first_header_sent = 0;
}

void h2_close(void) {
	first_header_sent = 0;
}

// encode a header frame
// frame - http2 frame
// return offset for the end of frame
static uint32_t h2_encode_header(uint8_t *frame, int len) {
	assert(frame);

	// server data
	DnsServer *srv = server_get();
	assert(srv);
	assert(srv->path);
	assert(srv->host);

	uint8_t *ptr = frame + sizeof(H2Frame);
	uint8_t sz;

//	HEADER(":method", "POST");
	*ptr++ = 3 | 0x80;

//	HEADER(":path", srv->path);
	if (!first_header_sent) {
		*ptr++ = 4 | 0x40;
		sz = strlen(srv->path);
		*ptr++ = sz;
		memcpy(ptr, srv->path, sz);
		ptr += sz;
	}
	else
		*ptr++ = 65 | 0x80;

// 	HEADER(":authority", srv->host);
	if (!first_header_sent) {
		*ptr++ = 1 | 0x40;
		sz = (uint8_t) strlen(srv->host);
		*ptr++ = sz;
		memcpy(ptr, srv->host, sz);
		ptr += sz;
	}
	else
		*ptr++ = 64 | 0x80;

//	HEADER(":scheme", "https");
	*ptr++ = 7 | 0x80;

//	HEADER("accept", "application/dns-message");
	if (!first_header_sent) {
		*ptr++ = 19 | 0x40;
		*ptr++ = 23;
		memcpy(ptr, "application/dns-message", 23);
		ptr += 23;
	}
	else
		*ptr++ = 63 | 0x80;


//	HEADER("content-type", "application/dns-message");
	if (!first_header_sent) {
		*ptr++ = 31 | 0x40;
		*ptr++ = 23;
		memcpy(ptr, "application/dns-message", 23);
		ptr += 23;
	}
	else
		*ptr++ = 62 | 0x80;

	// Literal Header Field without Indexing - indexed name
	char slen[20];
	sprintf(slen, "%d", len);
	*ptr++ = 0x0f; // 28 represented as 4-bit encoded
	*ptr++ = 28 - 15; //13;
	sz = strlen(slen);
	*ptr++ = sz;
	memcpy(ptr, slen, sz);
	ptr += sz;

//disabled	HEADER("pragma", "no-cache");
//disabled	HEADER("te", "trailers");
	ptrdiff_t length = ptr - (frame + sizeof(H2Frame));

	// add the frame header
	H2Frame *frm = (H2Frame *) frame;
	h2frame_set_length(frm, length);
	frm->type = H2_TYPE_HEADERS;
	frm->flag = H2_FLAG_END_HEADERS;// | H2_FLAG_END_STREAM;
	h2frame_set_stream(frm, stream_id);
	first_header_sent = 1;

//print_mem(frame, sizeof(H2Frame) + length);
	return sizeof(H2Frame) + length;
}

// return length of consumed data
static int extract_number(uint8_t *ptr, uint8_t prefix, unsigned *value) {
	int rv = 1;
	unsigned m = 0;
	*value = *ptr & prefix;
	if (*value == prefix) {
		do {
			ptr++;
			*value += ((unsigned) (*ptr & 127)) << m;
			m += 7;
			rv++;
		}
		while (*ptr & 0x80);
	}

	return rv;
}


static void printh(char* fmt, ...) {
	if ((arg_debug || arg_debug_header || printing) && arg_id == -1) {
		va_list args;
		va_start(args,fmt);
		vprintf(fmt, args);
		va_end(args);
	}
}

// return length of consumed data
static uint8_t extract_string(uint8_t *ptr) {
	unsigned retval;
//printf("extract string from 0x%02x\n", *ptr);
	// string length
	if (*ptr & 0x80) { // huiffman encoding
		*ptr &= 0x7f;
		unsigned value;
		unsigned rv  = extract_number(ptr, 0x7f, &value);
		ptr += rv;
		char *out_str = huffman_search(ptr, value);
		printh("  %s", out_str);
		retval = value + rv;
	}
	else { // regular string
		unsigned value;
		unsigned rv  = extract_number(ptr, 0x7f, &value);
//printf("number %u, bytes %u\n", value, rv);
		ptr += rv;
		char str[value + 1];
		memset(str, 0, value + 1);
		memcpy(str, ptr, value);
		printh("  %s", str);
		retval = value + rv;
	}

	return retval;
}

static uint32_t h2_decode_header(uint8_t *frame) {
	// http2 frame
	H2Frame frm;
	memcpy(&frm, frame, sizeof(H2Frame));
	int offset = sizeof(H2Frame);
	if (frm.type != H2_TYPE_HEADERS) {
		fprintf(stderr, "Not a http2 header\n");
		return 0;
	}

	if (arg_debug || arg_debug_header)
		printf("-----------------------------\n");

	size_t len = h2frame_extract_length(&frm);

	uint8_t flg = frm.flag;
	uint8_t pad = 0;
	uint32_t str = h2frame_extract_stream(&frm);
//todo		if (len > sizeof blk)
//			return (EXIT_FAILURE); /* DIY */

	uint8_t *ptr = frame + sizeof(H2Frame);
//print_mem(ptr, len);
	int cnt = 0;
	while (cnt < len) {
		if (arg_debug || arg_debug_header)
			printf("|");
//printf("procesing 0x%02x ", *ptr);
		if (*ptr & 0x80) { // indexed header field
			unsigned index;
			int rv = extract_number(ptr, 0x7f, &index);
			HpackStatic *hp = hpack_static_get(index);
			if (!hp)
				printh("Unknown indexed header field 0x%02x, position %u\n", *ptr, cnt);
			else
				printh("  %s:  %s\n", hp->name, hp->value);
			ptr += rv;
			cnt += rv;
		}
		else if (*ptr & 0x40) {  // literal header
			unsigned index;
			int rv = extract_number(ptr, 0x3f, &index);
			if (index == 54) { // server: -> turn on printing
				printing = 1;
				if (!(arg_debug || arg_debug_header))
					printf(" ");
			}

			HpackStatic *hp = hpack_static_get(index);
			ptr += rv;
			cnt += rv;

			if (!hp) {
				// read two strings
				uint8_t rv = extract_string(ptr);
				printh(":");
				ptr += rv;
				cnt += rv;
				rv = extract_string(ptr);
				printh("\n");
				ptr += rv;
				cnt += rv;
			}
			else {
				printh("  %s: ", hp->name);
				uint8_t rv = extract_string(ptr);
				printh("\n");
				ptr += rv;
				cnt += rv;
			}
			printing = 0;
		}
		else if (*ptr & 0x20) { // dynamic table size update
			unsigned value;
			int rv = extract_number(ptr, 0x1f, &value);
			printh("  (HPACK dynamic table size: %u)\n", value);
			ptr += rv;
			cnt += rv;
		}
		else if (*ptr & 0x10) { // literal header field never indexed
			unsigned index;
			int rv = extract_number(ptr, 0x0f, &index);
			if (index == 54) // server: -> turn on printing
				printing = 1;
			HpackStatic *hp = hpack_static_get(index);
			ptr += rv;
			cnt += rv;

			if (!hp) {
				// read two strings
				uint8_t rv = extract_string(ptr);
				printh(":");
				ptr += rv;
				cnt += rv;
				rv = extract_string(ptr);
				printh("\n");
				ptr += rv;
				cnt += rv;
			}
			else {
				printh("  %s: ", hp->name);

				uint8_t rv = extract_string(ptr);
				printh("\n");
				ptr += rv;
				cnt += rv;
			}
			printing = 0;
		}
		else if ((*ptr & 0xf0) == 0) { // literal header field without indexing
			unsigned index;
			int rv = extract_number(ptr, 0x0f, &index);
			if (index == 54) // server: -> turn on printing
				printing = 1;
			HpackStatic *hp = hpack_static_get(index);
			ptr += rv;
			cnt += rv;

			if (!hp) {
				// read two strings
				uint8_t rv = extract_string(ptr);
				printh(":");
				ptr += rv;
				cnt += rv;
				rv = extract_string(ptr);
				printh("\n");
				ptr += rv;
				cnt += rv;
			}
			else {
				printh("  %s:", hp->name);

				uint8_t rv = extract_string(ptr);
				printh("\n");
				ptr += rv;
				cnt += rv;
			}
			printing = 0;
		}
		else {
			printh("unknown field 0x%02x, position %u\n", *ptr, cnt);
			ptr++;
			cnt++;
		}
	}
	if (arg_debug || arg_debug_header)
		printf("-----------------------------\n");
}


// encode a data frame
// frame - http2 frame
// data and length
// using the same session id as the last encoded header frame; ending the stream
// return offset for the end of the frame
static uint32_t h2_encode_data(uint8_t *frame, uint8_t *data, unsigned length) {
	assert(frame);
	assert(data);
	assert(length);

	// build header
	H2Frame *frm = (H2Frame *) frame;
	h2frame_set_length(frm, length);
	frm->type = H2_TYPE_DATA;
	frm->flag = H2_FLAG_END_STREAM;
	h2frame_set_stream(frm, stream_id);
	memcpy(frame + sizeof(H2Frame), data, length);

	return length + sizeof(H2Frame);
}

// decode a data frame
// frame - http2 frame
// offset - offset to data section in frame
// length - length of data section
// return offset for the end of the frame
uint32_t h2_decode_data(uint8_t *frame, uint32_t *offset, uint32_t *length) {
	assert(frame);
	assert(length);
	*offset = 0;
	*length = 0;

	// decode header
	// http2 frame
	H2Frame frm;
	memcpy(&frm, frame, sizeof(H2Frame));
	int rv = sizeof(H2Frame);
	if (frm.type != H2_TYPE_DATA) {
		fprintf(stderr, "Not a data frame\n");
		return 0;
	}

	uint8_t flg = frm.flag;
	uint8_t pad = 0;
//	uint32_t stream = h2frame_extract_stream(&frm);
//todo:  check the current streamid
	*length = h2frame_extract_length(&frm);
	*offset = rv;

	if (flg & H2_FLAG_PADDED)
		rv += 1;

	*offset = rv;
	return rv + *length + pad;
}


static uint8_t buf_query[MAXBUF];
// returns -1 if error
int h2_connect(void) {
	stream_id = 0;
	uint8_t connect[] = {
		0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
		0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x00, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00,
		0x00, 0x40, 0x00, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x00, 0x01,
		0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00,
		0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x05, 0x02,
		0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00,
		0x0b, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00,
		0x00, 0x00, 0x00, 0xf0
	};

	if (arg_debug || arg_debug_h2) {
		print_time();
		printf("(%d) h2 tx connect\n", arg_id);
	}

	ssl_tx(connect, sizeof(connect));
	int rv = h2_exchange(buf_query, stream_id);
	stream_id = 13;
	return rv;
}

// the result message is placed in res, the length of the message is returned
// returns -1 if error
int h2_send_exampledotcom(uint8_t *req) {
	stream_id += 2;

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

	uint32_t len = h2_encode_header(buf_query, sizeof(dnsmsg));
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx", (H2Frame *) buf_query);

	int len2 = h2_encode_data(buf_query + len, dnsmsg, sizeof(dnsmsg));
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx query", (H2Frame *) (buf_query + len));

	ssl_tx(buf_query, len + len2);
	return h2_exchange(req, stream_id);
}


// the result message is placed in req, the length of the message is returned
// returns -1 if error
int h2_send_query(uint8_t *req, int cnt) {
	stream_id += 2;
	uint32_t len = h2_encode_header(buf_query, cnt);
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx", (H2Frame *) buf_query);

	int len2 = h2_encode_data(buf_query + len, req, cnt);
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx query", (H2Frame *) (buf_query + len));
	ssl_tx(buf_query, len + len2);

	return h2_exchange(req, stream_id);
}

// returns -1 if error
int h2_send_ping(void) {
	uint8_t frame[] = {0, 0, 8, 6,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx", (H2Frame *) frame);

	ssl_tx(frame, sizeof(frame));
	return h2_exchange(buf_query, 0);
}

// copy rx data in response and return the length
// return -1 if error
int h2_exchange(uint8_t *response, uint32_t stream) {
	assert(response);
	int retval = 0;

	uint8_t buf[MAXBUF];
	while (1) {
		fd_set readfds;
		FD_ZERO(&readfds);
		int fd = ssl_get_socket();
		FD_SET(fd, &readfds);
		struct timeval timeout;
		timeout.tv_sec = H2_TIMEOUT;
		timeout.tv_usec = 0;

		int rv = select(fd + 1, &readfds, NULL, NULL, &timeout);
		if (rv < 0)
			return -1;
		if (rv == 0) {
			if (arg_id > 0)
				rlogprintf("Error: h2 timeout\n");
			else
				fprintf(stderr, "Error: h2 timeout\n");
			if (ssl_state == SSL_OPEN)
				ssl_close();
			return -1;
		}

		if (FD_ISSET(fd, &readfds)) {
			int rv = ssl_rx(buf);
			if (rv == 0) {
				if (ssl_state == SSL_OPEN)
					ssl_close();
				return 0;
			}
			// todo: handle an incomplete frame

			if (arg_debug) {
				print_time();
				printf("(%d) h2 rx %d bytes\n", arg_id, rv);
				print_mem(buf, rv);
			}

			int offset = 0;
			while (offset < rv) {
				H2Frame *frm = (H2Frame *) (buf + offset);

				if (arg_debug || arg_debug_h2)
					h2frame_print(arg_id, "rx", frm);

				// go away conditions
				if (frm->type == H2_TYPE_GOAWAY) {
					ssl_close();
					return 0;
				}
				// reset strean - something is very wrong!
				if (frm->type == H2_TYPE_RESET) {
					ssl_close();
					return 0;
				}
				else if (frm->type > H2_TYPE_MAX && strncmp((char *) frm, "HTTP", 4) == 0) {
					fprintf(stderr, "Error: invalid HTTP version\n");
					return -1;
				}

				// normal header type processing
				if (frm->type == H2_TYPE_HEADERS) {
					size_t len = h2frame_extract_length(frm);
					if (h2_first_header_len == 0) { // print header, don't include it in the average
						h2_decode_header((uint8_t *) frm);
						h2_first_header_len = len;
					}
					else {
						h2_header_total += len;
						h2_header_cnt++;
					}
				}
				else if (frm->type == H2_TYPE_DATA) {
					uint32_t offset;
					uint32_t length;
					h2_decode_data((uint8_t *) frm, &offset, &length);
					if (arg_debug)
						print_mem((uint8_t *) frm + offset, length);

					// copy response in buf_query_data
					if (length != 0) {
						memcpy(response, (uint8_t *) frm + offset, length);
						retval = length;
					}
				}
				// ping response - do nothing
				else if (frm->type == H2_TYPE_PING && frm->flag & H2_FLAG_END_STREAM)
					return 0;

				// ping request - set end stream flag and return the packet
				else if (frm->type == H2_TYPE_PING && (frm->flag & H2_FLAG_END_STREAM) == 0) {
					frm->flag |= H2_FLAG_END_STREAM;
					if (arg_debug || arg_debug_h2)
						h2frame_print(arg_id, "tx", frm);

					ssl_tx((uint8_t *) frm, rv - offset);
					if (stream == 0)
						return 0;

					frm->flag &= ~H2_FLAG_END_STREAM;
				}

				if (frm->flag & H2_FLAG_END_STREAM)
					return retval; // disregard the rest!

				offset += sizeof(H2Frame) + h2frame_extract_length(frm);
				if (arg_debug) {
					print_time();
					printf("(%d) h2 rx data offset %d\n", arg_id, offset);
				}
			}
		}
	}

	return retval;
}



