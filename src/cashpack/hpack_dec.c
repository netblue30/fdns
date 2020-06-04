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
 * HPACK decoding.
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hpack.h"
#include "hpack_priv.h"

int
HPD_putc(HPACK_CTX, char c)
{

	EXPECT(ctx, BIG, ctx->buf_len > 0);
	*ctx->buf = c;
	ctx->buf++;
	ctx->buf_len--;
	return (0);
}

int
HPD_puts(HPACK_CTX, const char *str, size_t len)
{

	assert(str[len] == '\0');
	return (HPD_cat(ctx, str, len + 1));
}

int
HPD_cat(HPACK_CTX, const char *str, size_t len)
{

	EXPECT(ctx, BIG, ctx->buf_len >= len);
	(void)memcpy(ctx->buf, str, len);
	ctx->buf += len;
	ctx->buf_len -= len;
	return (0);
}

void
HPD_notify(HPACK_CTX)
{

	assert(ctx->fld.nam != NULL);
	assert(ctx->fld.val != NULL);
	assert(ctx->fld.nam_sz > 0);
	assert(ctx->fld.nam[ctx->fld.nam_sz] == '\0');
	assert(ctx->fld.val[ctx->fld.val_sz] == '\0');

	CALLBACK(ctx, HPACK_EVT_NAME,  ctx->fld.nam, ctx->fld.nam_sz);
	CALLBACK(ctx, HPACK_EVT_VALUE, ctx->fld.val, ctx->fld.val_sz);
}
