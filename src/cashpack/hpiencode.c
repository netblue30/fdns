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
 */

#undef NDEBUG

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "hpack.h"
#include "hpack_priv.h"

int
main(int argc, const char **argv)
{
	struct hpack_encoding enc;
	struct hpack_ctx ctx;
	enum hpi_prefix_e pfx;
	enum hpi_pattern_e pat;
	uint16_t val;
	uint8_t buf[8];

	/* ignore the program name */
	argc--;

	assert(argc == 2);

	pfx = 0;
	pat = 0;

#define HPP(nm, px, pt)				\
	if (!strcasecmp(#nm, argv[1])) {	\
		pfx = px;			\
		pat = pt;			\
	}
#include "tbl/hpack_tbl.h"
#undef HPP

	assert(pfx != 0);

	val = atoi(argv[2]);

	(void)memset(&enc, 0, sizeof enc);
	enc.buf = buf;
	enc.buf_len = sizeof buf;

	(void)memset(&ctx, 0, sizeof ctx);
	ctx.arg.enc = &enc;
	ctx.ptr.cur = buf;

	HPI_encode(&ctx, pfx, pat, val);

	assert(ctx.len > 0);

	while (ctx.len > 0) {
		printf("%02x", *(uint8_t *)enc.buf);
		enc.buf = (uint8_t *)enc.buf + 1;
		ctx.len--;
	}
	puts("");

	return (0);
}
