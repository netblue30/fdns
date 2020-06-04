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
 * HPACK encoding.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hpack.h"
#include "hpack_priv.h"

inline void
HPE_putb(HPACK_CTX, uint8_t b)
{

	assert(ctx->len < ctx->arg.enc->buf_len);

	*ctx->ptr.cur = b;
	ctx->ptr.cur++;
	ctx->len++;

	if (ctx->len == ctx->arg.enc->buf_len)
		HPE_send(ctx);
}

void
HPE_bcat(HPACK_CTX, const void *buf, size_t len)
{
	size_t sz;

	assert(buf != NULL);

	while (len > 0) {
		sz = ctx->arg.enc->buf_len - ctx->len;
		if (sz > len)
			sz = len;

		(void)memcpy(ctx->ptr.cur, buf, sz);
		ctx->ptr.cur += sz;
		ctx->len += sz;
		len -= sz;

		if (ctx->len == ctx->arg.enc->buf_len)
			HPE_send(ctx);
	}
}

void
HPE_send(HPACK_CTX)
{

	if (ctx->len == 0)
		return;

	CALLBACK(ctx, HPACK_EVT_DATA, ctx->arg.enc->buf, ctx->len);
	ctx->ptr.cur = ctx->arg.enc->buf;
	ctx->len = 0;
}
