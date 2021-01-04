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

#ifndef H2FRAME_H
#define H2FRAME_H
#include "fdns.h"
#include "timetrace.h"

//
// http2 header definitions
//
typedef struct h2frame_t {
	uint8_t len[3];

#define H2_TYPE_DATA		0x00
#define H2_TYPE_HEADERS	0x01
#define H2_TYPE_PRIORITY	0x02
#define H2_TYPE_RESET	0x03
#define H2_TYPE_SETTINGS 	0x04
#define H2_TYPE_PUSH_PROMISE	0x05
#define H2_TYPE_PING 		0x06
#define H2_TYPE_GOAWAY	0x07
#define H2_TYPE_WIN_UPDATE	0x08
#define H2_TYPE_MAX		0x08 // the last one
	uint8_t type;

#define H2_FLAG_END_STREAM	0x01
#define H2_FLAG_END_HEADERS	0x04
#define H2_FLAG_PADDED	0x08
#define H2_FLAG_PRIORITY	0x20
	uint8_t flag;

	uint8_t stream[4];
} H2Frame;

static inline char *h2frame_type2str(uint8_t type) {
	switch (type) {
	case H2_TYPE_DATA:
		return "DATA";
	case H2_TYPE_HEADERS:
		return "HEADERS";
	case H2_TYPE_PRIORITY:
		return "PRIORITY";
	case H2_TYPE_RESET:
		return "RESET";
	case H2_TYPE_SETTINGS:
		return "SETTINGS";
	case H2_TYPE_PUSH_PROMISE:
		return "PUSH-PROMISE";
	case H2_TYPE_PING:
		return "PING";
	case H2_TYPE_GOAWAY:
		return "GOAWAY";
	case H2_TYPE_WIN_UPDATE:
		return "WINDOW-UPDATE";
	};
	return "UNKNOWN";
}

static inline uint32_t h2frame_extract_stream(H2Frame *frm) {
	uint32_t rv = frm->stream[0] << 24 | frm->stream[1] << 16 | frm->stream[2] << 8 | frm->stream[3];
	return rv;
}

static inline uint32_t h2frame_extract_length(H2Frame *frm) {
	uint32_t rv = frm->len[0] << 16 | frm->len[1] << 8 | frm->len[2];
	return rv;
}

static inline void h2frame_set_stream(H2Frame *frm, uint32_t stream) {
	frm->stream[3] = stream & 0xFF;
	frm->stream[2] = (stream >> 8) & 0xFF;
	frm->stream[1] = (stream >> 16) & 0xFF;
	frm->stream[0] = (stream >> 24) & 0x7F;
}

static inline void h2frame_set_length(H2Frame *frm, uint32_t length) {
	frm->len[2] = length & 0xFF;
	frm->len[1] = (length >> 8) & 0xFF;
	frm->len[0]  = (length >> 16) & 0xFF;
}

static inline void h2frame_print(int id, const char *direction, H2Frame *frm) {
	assert(frm);
	assert(direction);

	uint32_t len = h2frame_extract_length(frm);
	uint32_t stream = h2frame_extract_stream(frm);
	print_time();
	if (frm->type != H2_TYPE_WIN_UPDATE)
		printf("(%d) h2 %s s %u, len %u, 0x%02u %s, 0x%02u (",
		       id,
		       direction,
		       stream,
		       len,
		       frm->type, h2frame_type2str(frm->type),
		       frm->flag);
	else {
		uint8_t *wstart = (uint8_t *) frm + sizeof(H2Frame);
		uint32_t window;
		memcpy(&window, wstart, 4);
		window &= 0x7fffffff;
		window = ntohl(window);
		printf("(%d) h2 %s s %u, len %u, 0x%02u %s(%d), 0x%02u (",
		       id,
		       direction,
		       stream,
		       len,
		       frm->type, h2frame_type2str(frm->type), window,
		       frm->flag);
	}

	if (frm->flag & H2_FLAG_END_STREAM)
		printf("end stream,");
	if (frm->flag & H2_FLAG_END_HEADERS)
		printf("end headers,");
	if (frm->flag & H2_FLAG_PADDED)
		printf("padded,");
	if (frm->flag & H2_FLAG_PRIORITY)
		printf("priority,");
	printf(")\n");
	fflush(0);
}

#endif
