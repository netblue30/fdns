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
 * HPACK Indexing Tables (RFC 7541 Section 2.3)
 */

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hpack.h"
#include "hpack_assert.h"
#include "hpack_priv.h"

#define HPT_HEADERSZ (HPACK_OVERHEAD - 2) /* account for 2 null bytes */

#define MOVE(he, off)	(void *)(uintptr_t)((uintptr_t)(he) + (off))
#define JUMP(he, off)	(void *)((uintptr_t)(he) + HPT_HEADERSZ + (off))
#define DIFF(a, b)	((uintptr_t)b - (uintptr_t)a)

static const struct hpt_field hpt_static[] = {
#define HPS(n, v)				\
	{					\
		.nam = n,			\
		.val = v,			\
		.nam_sz = sizeof(n) - 1,	\
		.val_sz = sizeof(v) - 1,	\
	},
#include "tbl/hpack_static.h"
#undef HPS
};

/**********************************************************************
 * Tables lookups
 */

static struct hpt_entry *
hpt_dynamic(struct hpack *hp, size_t idx)
{
	struct hpt_entry *he, tmp;
	ptrdiff_t off;

	he = HPACK_TBL(hp);
	off = 0;

	assert(idx > 0);
	assert(idx <= hp->cnt);

	while (1) {
		(void)memcpy(&tmp, he, HPT_HEADERSZ);
		assert(tmp.magic == HPT_ENTRY_MAGIC);
		assert(tmp.pre_sz == off);
		assert(tmp.nam_sz > 0);
		if (--idx == 0)
			return (he);
		off = HPACK_OVERHEAD + tmp.nam_sz + tmp.val_sz;
		he = MOVE(he, off);
	}
}

int
HPT_search(HPACK_CTX, size_t idx, struct hpt_field *hf)
{
	const struct hpt_entry *he;
	struct hpt_entry tmp;

	assert(idx != 0);
	if (idx <= HPACK_STATIC) {
		(void)memcpy(hf, &hpt_static[idx - 1], sizeof *hf);
		return (0);
	}

	idx -= HPACK_STATIC;
	EXPECT(ctx, IDX, idx <= ctx->hp->cnt);

	he = hpt_dynamic(ctx->hp, idx);
	assert(he != NULL);
	assert(hf != NULL);
	(void)memcpy(&tmp, he, HPT_HEADERSZ);
	hf->nam_sz = tmp.nam_sz;
	hf->val_sz = tmp.val_sz;
	hf->nam = JUMP(he, 0);
	hf->val = JUMP(he, tmp.nam_sz + 1);
	return (0);
}

void
HPT_foreach(HPACK_CTX, int flg)
{
	const struct hpt_entry *he, *tbl;
	const struct hpt_field *hf;
	struct hpt_entry tmp;
	ptrdiff_t off;
	size_t i;

	if (flg & HPT_FLG_STATIC)
		for (i = 0, hf = hpt_static; i < HPACK_STATIC; i++, hf++) {
			CALLBACK(ctx, HPACK_EVT_FIELD, NULL, 0);
			CALLBACK(ctx, HPACK_EVT_NAME, hf->nam, hf->nam_sz);
			CALLBACK(ctx, HPACK_EVT_VALUE, hf->val, hf->val_sz);
		}

	if (~flg & HPT_FLG_DYNAMIC)
		return;

	off = 0;
	tbl = HPACK_TBL(ctx->hp);
	he = tbl;
	for (i = 0; i < ctx->hp->cnt; i++) {
		assert(DIFF(tbl, he) < ctx->hp->sz.len);
		(void)memcpy(&tmp, he, HPT_HEADERSZ);
		assert(tmp.magic == HPT_ENTRY_MAGIC);
		assert(tmp.pre_sz == off);
		assert(tmp.nam_sz > 0);
		off = HPACK_OVERHEAD + tmp.nam_sz + tmp.val_sz;
		CALLBACK(ctx, HPACK_EVT_FIELD, NULL, off);
		CALLBACK(ctx, HPACK_EVT_NAME, JUMP(he, 0), tmp.nam_sz);
		CALLBACK(ctx, HPACK_EVT_VALUE, JUMP(he, tmp.nam_sz + 1),
		    tmp.val_sz);
		he = MOVE(he, off);
	}

	assert(DIFF(tbl, he) == ctx->hp->sz.len);
}

/**********************************************************************
 * Resize
 */

void
HPT_adjust(struct hpack_ctx *ctx, size_t len)
{
	struct hpack *hp;
	struct hpt_entry *he;
	struct hpt_entry tmp;
	size_t sz, lim, n;

	hp = ctx->hp;
	assert(hp->sz.lim <= (ssize_t)hp->sz.max ||
	    hp->sz.nxt > (ssize_t)hp->sz.max);

	if (hp->cnt == 0)
		return;

	he = hpt_dynamic(hp, hp->cnt);
	lim = HPACK_LIMIT(hp);

	n = 0;
	while (hp->cnt > 0 && len > lim) {
		(void)memcpy(&tmp, he, HPT_HEADERSZ);
		assert(tmp.magic == HPT_ENTRY_MAGIC);
		assert(tmp.nam_sz > 0);
		sz = HPACK_OVERHEAD + tmp.nam_sz + tmp.val_sz;
		len -= sz;
		hp->sz.len -= sz;
		hp->cnt--;
		he = MOVE(he, -tmp.pre_sz);
		n++;
	}

	if (n > 0)
		CALLBACK(ctx, HPACK_EVT_EVICT, NULL, n);

	if (hp->cnt == 0)
		assert(hp->sz.len == 0);
	else
		assert(hp->sz.len > 0);
}

/**********************************************************************
 * Insert
 */

static unsigned
hpt_fit(HPACK_CTX, size_t len)
{
	struct hpack *hp;

	hp = ctx->hp;
	assert(hp->sz.lim <= (ssize_t) hp->sz.max);

	/* fitting the new field may require eviction */
	HPT_adjust(ctx, hp->sz.len + len);

	/* does the new field even fit alone? */
	if (len > HPACK_LIMIT(hp)) {
		assert(hp->sz.len == 0);
		assert(hp->cnt == 0);
		return (0);
	}
	return (1);
}

static unsigned
hpt_overlap(const struct hpack *hp, const char *buf, size_t len)
{
	uintptr_t bgn, end, pos;

	bgn = (uintptr_t)HPACK_TBL(hp);
	pos = (uintptr_t)buf;
	end = bgn + hp->sz.len;

	if (pos >= bgn && pos < end) {
		pos += len;
		assert(pos >= bgn && pos < end);
		return (1);
	}

	pos += len;
	assert(pos < bgn || pos >= end);
	return (0);
}

static void
hpt_move_evicted(HPACK_CTX, const char *nam, size_t nam_sz, size_t len)
{
	struct hpack *hp;
	char tmp[64], *nam_ptr;
	void *tbl_ptr;
	size_t sz, mv;

	hp = ctx->hp;
	assert(hp->magic == ENCODER_MAGIC);

	tbl_ptr = HPACK_TBL(hp);
	nam_ptr = JUMP(tbl_ptr, 0);
	nam_sz++; /* null character */
	mv = 0;

	/* NB: from RFC 7541 section 4.4.
	 * A new entry can reference the name of an entry in the dynamic table
	 * that will be evicted when adding this new entry into the dynamic
	 * table.  Implementations are cautioned to avoid deleting the
	 * referenced name if the referenced entry is evicted from the dynamic
	 * table prior to inserting the new entry.
	 */
	while (nam_sz > 0) {
		sz = nam_sz < sizeof tmp ? nam_sz : sizeof tmp;
		mv += sz;

		(void)memcpy(tmp, nam, sz);
		(void)memmove(MOVE(tbl_ptr, sz), tbl_ptr, hp->sz.len);
		(void)memcpy(nam_ptr, tmp, sz);

		len -= sz;
		nam += sz;
		nam_sz -= sz;
		tbl_ptr = MOVE(tbl_ptr, sz);
	}

	assert(len > HPT_HEADERSZ);
	(void)memmove(MOVE(tbl_ptr, len), tbl_ptr, hp->sz.len);
}

void
HPT_index(HPACK_CTX)
{
	struct hpack *hp;
	struct hpt_entry *tbl_ptr;
	void *nam_ptr, *val_ptr;
	size_t len, nam_sz, val_sz;
	unsigned ovl;

	assert(ctx->fld.nam != NULL);
	assert(ctx->fld.val != NULL);
	assert(ctx->fld.nam_sz > 0);

	nam_sz = ctx->fld.nam_sz;
	val_sz = ctx->fld.val_sz;
	assert(ctx->fld.nam[nam_sz] == '\0');
	assert(ctx->fld.val[val_sz] == '\0');

	hp = ctx->hp;
	ovl = hpt_overlap(hp, ctx->fld.nam, nam_sz);
	assert(!hpt_overlap(hp, ctx->fld.val, val_sz));

	len = HPACK_OVERHEAD + nam_sz + val_sz;
	if (!hpt_fit(ctx, len))
		return;

	tbl_ptr = HPACK_TBL(hp);
	nam_ptr = JUMP(tbl_ptr, 0);
	val_ptr = JUMP(tbl_ptr, nam_sz + 1);
	tbl_ptr->pre_sz = len;

	if (ovl)
		hpt_move_evicted(ctx, ctx->fld.nam, nam_sz, len);
	else if (hp->cnt > 0)
		(void)memmove(MOVE(tbl_ptr, len), tbl_ptr, hp->sz.len);

	if (!ovl)
		(void)memcpy(nam_ptr, ctx->fld.nam, nam_sz + 1);
	(void)memcpy(val_ptr, ctx->fld.val, val_sz + 1);

	tbl_ptr->magic = HPT_ENTRY_MAGIC;
	tbl_ptr->pre_sz = 0;
	tbl_ptr->nam_sz = nam_sz;
	tbl_ptr->val_sz = val_sz;
	hp->sz.len += len;
	hp->cnt++;

	CALLBACK(ctx, HPACK_EVT_INDEX, NULL, len);
}

/**********************************************************************
 * Decode
 */

int
HPT_decode(HPACK_CTX, size_t idx)
{
	struct hpt_field hf;

	EXPECT(ctx, IDX, idx > 0);
	(void)memset(&hf, 0, sizeof hf);
	CALL(HPT_search, ctx, idx, &hf);
	assert(hf.nam != NULL);
	assert(hf.val != NULL);
	assert(hf.nam_sz > 0);

	ctx->fld.nam = ctx->buf;
	ctx->fld.nam_sz = hf.nam_sz;
	CALL(HPD_puts, ctx, hf.nam, hf.nam_sz);

	ctx->fld.val = ctx->buf;
	ctx->fld.val_sz = hf.val_sz;
	CALL(HPD_puts, ctx, hf.val, hf.val_sz);

	HPD_notify(ctx);
	return (0);
}

int
HPT_decode_name(HPACK_CTX)
{
	struct hpt_field hf;

	assert(ctx->fld.nam == ctx->buf);
	assert(ctx->hp->state.idx != 0);
	(void)memset(&hf, 0, sizeof hf);
	CALL(HPT_search, ctx, ctx->hp->state.idx, &hf);
	assert(hf.nam != NULL);
	assert(hf.nam_sz > 0);

	return (HPD_puts(ctx, hf.nam, hf.nam_sz));
}
