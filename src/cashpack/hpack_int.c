/*-
 * Copyright (c) 2016-2017 Dridi Boukelmoune
 * All rights reserved.
 *
 * Author: Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * HPACK Integer representation (RFC 7541 Section 5.1)
 *
 * The implementation uses 16-bit unsigned values because 255 (2^8 - 1) octets
 * would have been too little for literal header values (mostly for URLs and
 * cookies) and 65535 (2^16 - 1) octets (65KB!!) seem overkill enough.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "hpack.h"
#include "hpack_assert.h"
#include "hpack_priv.h"

int
HPI_decode(HPACK_CTX, enum hpi_prefix_e pfx, uint16_t *val)
{
	struct hpack_state *hs;
	uint16_t n;
	uint8_t b, mask;

	assert(pfx >= 4 && pfx <= 7);
	assert(val != NULL);

	hs = &ctx->hp->state;
	if (hs->bsy)
		assert(hs->magic == INT_STATE_MAGIC);
	else
		hs->magic = INT_STATE_MAGIC;

	assert(ctx->len > 0 || ctx->hp->state.stp != HPACK_STP_FLD_INT);
	EXPECT(ctx, BUF, ctx->len > 0);
	if (!hs->bsy) {
		mask = (1 << pfx) - 1;
		hs->stt.hpi.v = *ctx->ptr.blk & mask;
		ctx->ptr.blk++;
		ctx->len--;

		if (hs->stt.hpi.v < mask) {
			*val = hs->stt.hpi.v;
			return (0);
		}
		hs->stt.hpi.m = 0;
		hs->bsy = 1;
	}

	do {
		EXPECT(ctx, BUF, ctx->len > 0);
		b = *ctx->ptr.blk;
		n = hs->stt.hpi.v;
		if (hs->stt.hpi.m <= 16)
			n += (b & 0x7f) * (1 << hs->stt.hpi.m);
		else
			EXPECT(ctx, INT, (b & 0x7f) == 0);
		EXPECT(ctx, INT, hs->stt.hpi.v <= n);
		hs->stt.hpi.v = n;
		hs->stt.hpi.m += 7;
		ctx->ptr.blk++;
		ctx->len--;
	} while (b & 0x80);

	*val = hs->stt.hpi.v;
	hs->bsy = 0;
	return (0);
}

void
HPI_encode(HPACK_CTX, enum hpi_prefix_e pfx, enum hpi_pattern_e pat,
    uint16_t val)
{
	uint8_t mask;

	assert(pfx >= 4 && pfx <= 7);
	assert(ctx->len < ctx->arg.enc->buf_len);

	mask = (1 << pfx) - 1;
	if (val < mask) {
		HPE_putb(ctx, (uint8_t)(pat | val));
		return;
	}

	HPE_putb(ctx, pat | mask);
	val -= mask;
	while (val >= 0x80) {
		HPE_putb(ctx, 0x80 | (val & 0x7f));
		val >>= 7;
	}

	HPE_putb(ctx, (uint8_t)val);
}
