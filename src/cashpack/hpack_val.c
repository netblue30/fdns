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
 * Header field grammar validation (RFC 7230 Section 3.2)
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hpack.h"
#include "hpack_priv.h"

#define IS_VCHAR(c)		((uint8_t)c > 0x20 && (uint8_t)c < 0x7f)
#define IS_OBS_TEXT(c)		((uint8_t)c & 0x80)
#define IS_FIELD_VCHAR(c)	(IS_VCHAR(c) || IS_OBS_TEXT(c))
#define IS_FIELD_VALUE(c)	(c == ' ' || c == '\t' || IS_FIELD_VCHAR(c))

int
HPV_value(HPACK_CTX, const char *str, size_t len)
{
	uint8_t c;

	assert(str != NULL);
	while (len > 0) {
		c = (uint8_t)*str;
		/* RFC 7230 3.2.  Header Fields */
		EXPECT(ctx, CHR, c == '\t' || (c >= ' ' && c != 0x7f));
		assert(IS_FIELD_VALUE(c));
		str++;
		len--;
	}

	assert(*str == '\0');
	return (0);
}

int
HPV_token(HPACK_CTX, const char *str, size_t len)
{

	assert(str != NULL);
	assert(len > 0);

	/* RFC 7540 Section 8.1.2.1.  Pseudo-Header Fields */
	if (*str == ':') {
#define HPPH(hdr)					\
		if (!strncmp(str, hdr, len + 1))	\
				return (0);
#include "tbl/hpack_pseudo_headers.h"
#undef HPPH
		ctx->res = HPACK_RES_HDR;
		return (HPACK_RES_HDR);
	}

	while (len > 0) {
		/* RFC 7230 Section 3.2.6.  Field Value Components */
		EXPECT(ctx, CHR, IS_VCHAR(*str) &&
		    strchr("()<>@,;:\\\"/[]?={} ", *str) == NULL);
		/* RFC 7540 Section 8.1.2.  HTTP Header Fields */
		EXPECT(ctx, CHR, *str < 'A' || *str > 'Z');
		str++;
		len--;
	}

	assert(*str == '\0');
	return (0);
}
