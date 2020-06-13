// gcc -lhpack -o cashbld cashbld.c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include "../inc/hpack.h"
#include "h2frame.h"
#include "fdns.h"

static uint32_t stream_id;

#define MAX_HEADER_FIELDS 64
#define HEADER(name, value) fields[pos++] = (struct hpack_field){ \
		.nam = (name), \
		.val = (value), \
		.flg = HPACK_FLG_TYP_LIT | HPACK_FLG_NAM_HUF | HPACK_FLG_VAL_HUF \
	}


struct tmp_buf {
	char *data;
	size_t offset;
};

static void header_encode_cb(enum hpack_event_e evt, const char *buf, size_t len, void *priv) {
	struct tmp_buf *out = priv;
	switch (evt) {
	case HPACK_EVT_DATA:
		memcpy(out->data + out->offset, buf, len);
		out->offset += len;
		break;
	default:
		break;
	}
}

static void print_headers(enum hpack_event_e evt, const char *buf, size_t len, void *priv) {
	(void)priv;
	if (!arg_debug)
		return;

	/* print "\n${name}: ${value}" for each header field */

	switch (evt) {
	case HPACK_EVT_FIELD:
		printf("\n");
		break;
	case HPACK_EVT_VALUE:
		printf(": ");
	/* fall through */
	case HPACK_EVT_NAME:
		printf("    %s", buf);
		(void)len;
	/* fall through */
	default:
		/* ignore other events */
		break;
	}
}


struct hpack *hpe = NULL;
struct hpack *hpd = NULL;
void h2_init(void) {
	hpe = hpack_encoder(4096, -1, hpack_default_alloc);
	hpd = hpack_decoder(4096, -1, hpack_default_alloc);
}

void h2_close(void) {
	if (hpe != NULL) {
		hpack_free(&hpe);
		hpe = NULL;
	}
	if (hpd != NULL) {
		hpack_free(&hpd);
		hpd = NULL;
	}

}

// encode a header frame
// frame - http2 frame
// return offset for the end of frame
static uint32_t h2_encode_header(uint8_t *frame, int len) {
	assert(frame);

	char slen[20];
	sprintf(slen, "%d", len);

	// extract server data
	DnsServer *srv = server_get();
	assert(srv);
	assert(srv->path);
	assert(srv->host);


	// hpack encode
	struct hpack_field fields[MAX_HEADER_FIELDS];
	size_t pos = 0;

	HEADER(":method", "POST");
	HEADER(":path", srv->path);
	HEADER(":authority", srv->host);
	HEADER(":scheme", "https");
	HEADER("accept", "application/dns-message");
	HEADER("content-type", "application/dns-message");
	HEADER("content-length", slen); //"48");
	HEADER("pragma", "no-cache");
//	HEADER("te", "trailers");

	// encoding structure
	char hpack_buf[MAXBUF];
	struct tmp_buf buf = {
		frame + 9,	// frame header size 9
		0,
	};
	struct hpack_encoding enc;
	enc.fld = fields;
	enc.fld_cnt = pos;
	enc.buf = hpack_buf;
	enc.buf_len = MAXBUF;
	enc.cb = header_encode_cb,
	enc.priv = &buf,
	enc.cut = 0;

	// encoding
	int rv = hpack_encode(hpe, &enc);
	if (rv != HPACK_RES_OK) {
		fprintf(stderr, "hpack encoding error: %s\n", hpack_strerror(rv));
		exit(1);
	}

	// build header
	H2Frame *frm = (H2Frame *) frame;
	uint32_t length = buf.offset;
	h2frame_set_length(frm, length);
	frm->type = H2_TYPE_HEADERS;
	frm->flag = H2_FLAG_END_HEADERS;// | H2_FLAG_END_STREAM;
	h2frame_set_stream(frm, stream_id);

	return sizeof(H2Frame) + length;
}

// decode a header frame
// frame - http2 frame
// return offset for the end of frame
static uint32_t h2_decode_header(uint8_t *frame) {
	// http2 frame
	H2Frame frm;
	memcpy(&frm, frame, sizeof(H2Frame));
	int offset = sizeof(H2Frame);
	if (frm.type != H2_TYPE_HEADERS) {
		fprintf(stderr, "Not a header header\n");
		return 0;
	}

	uint8_t flg = frm.flag;
	uint8_t pad = 0;
	uint32_t str = h2frame_extract_stream(&frm);
	size_t len = h2frame_extract_length(&frm);
//todo		if (len > sizeof blk)
//			return (EXIT_FAILURE); /* DIY */

	uint8_t blk[4096];
	uint8_t buf[1024];
	struct hpack_decoding dec;
	dec.blk = blk;
	dec.blk_len = 0;
	dec.buf = buf;
	dec.buf_len = sizeof buf;
	dec.cb = print_headers;
	dec.priv = NULL;

	if (flg & H2_FLAG_PADDED)
		offset += 1;
	if (flg & H2_FLAG_PRIORITY)
		offset += 5;

	memcpy(blk, frame + offset, len);
	offset += len;

	/* decode the HPACK block */
	if (flg & H2_FLAG_END_HEADERS && arg_debug)
		printf("=== stream %u", str);

	dec.cut = ~flg & H2_FLAG_END_HEADERS;
	dec.blk_len = len;

	int rv = hpack_decode(hpd, &dec);
	if (rv < 0)
		return 0;

	if (flg & H2_FLAG_PADDED)
		offset += pad;
	if (arg_debug)
		printf("\n");
	return offset;
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
	uint32_t stream = h2frame_extract_stream(&frm);
//todo:  check the current streamid
	*length = h2frame_extract_length(&frm);
	*offset = rv;

	if (flg & H2_FLAG_PADDED)
		rv += 1;

	*offset = rv;
	return rv + *length + pad;
}


static uint8_t buf_query[MAXBUF];
void h2_connect(void) {
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

	if (arg_debug) {
		print_time();
		printf("(%d) h2 send connect\n", arg_id);
	}

	ssl_tx(connect, sizeof(connect));
	h2_exchange(buf_query);
	stream_id = 13;
}

void h2_send_exampledotcom(void) {
	stream_id += 2;

	uint8_t req[] = {
		0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f,
		0x6d, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x08, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00
	};
	uint32_t len = h2_encode_header(buf_query, sizeof(req));
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx", (H2Frame *) buf_query);

	int len2 = h2_encode_data(buf_query + len, req, sizeof(req));
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx query", (H2Frame *) (buf_query + len));

	ssl_tx(buf_query, len + len2);
	int rv = h2_exchange(buf_query);
}



int h2_send_query(uint8_t *req, int cnt) {
	stream_id += 2;
	uint32_t len = h2_encode_header(buf_query, cnt);
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx", (H2Frame *) buf_query);

	int len2 = h2_encode_data(buf_query + len, req, cnt);
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx query", (H2Frame *) (buf_query + len));
	ssl_tx(buf_query, len + len2);

	return h2_exchange(req);
}

void h2_send_ping(void) {
	uint8_t frame[] = {0, 0, 8, 6,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	if (arg_debug || arg_debug_h2)
		h2frame_print(arg_id, "tx", (H2Frame *) frame);

	ssl_tx(frame, sizeof(frame));
	h2_exchange(buf_query);
}

// copy rx data in response and return the length
int h2_exchange(uint8_t *response) {
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
			return 0;
		if (rv == 0) {
			if (arg_id > 0)
				rlogprintf("Error: h2 timeout\n");
			else
				fprintf(stderr, "Error: h2 timeout\n");
			if (ssl_state == SSL_OPEN)
				ssl_close();
			return 0;
		}

		if (FD_ISSET(fd, &readfds)) {
			int rv = ssl_rx(buf);
			if (rv == 0) {
				if (ssl_state == SSL_OPEN)
					ssl_close();
				return 0;
			}

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

				if (frm->type == H2_TYPE_HEADERS)
					h2_decode_header((uint8_t *) frm);
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
				else if (frm->type == H2_TYPE_PING && frm->flag & H2_FLAG_END_STREAM == 0) {
					frm->flag |= H2_FLAG_END_STREAM;
					ssl_tx((uint8_t *) frm, rv - offset);
					return 0;
				}
				else if (frm->type == H2_TYPE_GOAWAY) {
					ssl_close();
					return 0;
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



