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
 * HPACK: Header Compression for HTTP/2 (RFC 7541)
 */

#include <assert.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hpack.h"
#include "hpack_assert.h"
#include "hpack_priv.h"

#define OUT_OF_BITS (void)0;
#define FUNC_PTR(f) (const void *)(const uint8_t *)&(f)

/**********************************************************************
 * System allocator
 */

static void *
hpack_libc_malloc(size_t size, void *priv)
{

	(void)priv;
	return (malloc(size));
}

static void *
hpack_libc_realloc(void *ptr, size_t size, void *priv)
{

	(void)priv;
	return (realloc(ptr, size));
}

static void
hpack_libc_free(void *ptr, void *priv)
{

	(void)priv;
	free(ptr);
}

static const struct hpack_alloc hpack_libc_alloc = {
	hpack_libc_malloc,
	hpack_libc_realloc,
	hpack_libc_free,
	NULL
};

const struct hpack_alloc *hpack_default_alloc = &hpack_libc_alloc;

/**********************************************************************
 * Memory management
 */

static struct hpack *
hpack_new(uint32_t magic, size_t mem, size_t max,
    const struct hpack_alloc *ha)
{
	struct hpack *hp;

	if (ha == NULL || ha->malloc == NULL || max > UINT16_MAX ||
	    mem > UINT16_MAX)
		return (NULL);

	assert(mem >= max || magic == ENCODER_MAGIC);

	hp = ha->malloc(sizeof *hp + mem, ha->priv);
	if (hp == NULL)
		return (NULL);

	(void)memset(hp, 0, sizeof *hp);
	hp->magic = magic;
	hp->ctx.hp = hp;
	(void)memcpy(&hp->alloc, ha, sizeof *ha);
	hp->sz.mem = mem;
	hp->sz.max = max;
	hp->sz.lim = -1;
	hp->sz.cap = -1;
	hp->sz.nxt = -1;
	hp->sz.min = -1;
	return (hp);
}

struct hpack *
hpack_encoder(size_t max, ssize_t lim, const struct hpack_alloc *ha)
{
	enum hpack_result_e res;
	struct hpack *hp, *tmp;
	size_t mem;

	mem = lim >= 0 ? (size_t)lim : max;
	hp = hpack_new(ENCODER_MAGIC, mem, max, ha);
	if (lim >= 0 && hp != NULL) {
		tmp = hp;
		res = hpack_limit(&tmp, lim);
		(void)res;
		assert(res == HPACK_RES_OK);
		assert(tmp == hp);
		assert(lim == hp->sz.cap);
	}
	return (hp);
}

struct hpack *
hpack_decoder(size_t max, ssize_t rsz, const struct hpack_alloc *ha)
{
	size_t mem;

	mem = rsz >= 0 ? (size_t)rsz : max;
	if (mem < max)
		mem = max;
	return (hpack_new(DECODER_MAGIC, mem, max, ha));
}

static enum hpack_result_e
hpack_realloc(struct hpack **hpp, size_t mem)
{
	struct hpack *hp;

	hp = *hpp;
	if (mem <= hp->sz.mem)
		return (HPACK_RES_OK);

	assert(hp->sz.len <= mem);
	if (hp->alloc.realloc == NULL)
		return (HPACK_RES_REA);

	hp = hp->alloc.realloc(hp, sizeof *hp + mem, hp->alloc.priv);
	if (hp == NULL)
		return (HPACK_RES_OOM);

	hp->ctx.hp = hp;
	hp->sz.mem = mem;
	*hpp = hp;
	return (HPACK_RES_OK);
}

enum hpack_result_e
hpack_resize(struct hpack **hpp, size_t len)
{
	struct hpack *hp;
	enum hpack_result_e res;
	size_t max, mem;

	if (hpp == NULL)
		return (HPACK_RES_ARG);

	hp = *hpp;
	if (hp == NULL)
		return (HPACK_RES_ARG);
	if (hp->magic != DECODER_MAGIC && hp->magic != ENCODER_MAGIC)
		return (HPACK_RES_ARG);

	if (hp->ctx.res != HPACK_RES_OK) {
		assert(hp->ctx.res == HPACK_RES_BLK);
		return (HPACK_RES_BSY);
	}

	max = hp->alloc.realloc == NULL ? hp->sz.mem : UINT16_MAX;
	mem = len;

	if (hp->magic == ENCODER_MAGIC) {
		if (hp->sz.lim >= 0) {
			assert(hp->sz.lim == hp->sz.cap);
			assert((size_t)hp->sz.lim <= hp->sz.mem);
			assert((size_t)hp->sz.lim >= hp->sz.len);
			mem = hp->sz.lim;
		}
		else if (hp->sz.cap >= 0) {
			assert((size_t)hp->sz.cap <= max);
			mem = hp->sz.cap;
		}
	}

	if (mem > max) {
		hp->magic = DEFUNCT_MAGIC;
		return (HPACK_RES_LEN);
	}

	res = hpack_realloc(&hp, mem);
	if (res != HPACK_RES_OK) {
		assert(*hpp == hp);
		hp->magic = DEFUNCT_MAGIC;
		return (res);
	}

	*hpp = hp;

	if (hp->sz.min < 0) {
		assert(hp->sz.nxt < 0);
		hp->sz.nxt = len;
		hp->sz.min = len;
	}
	else {
		assert(hp->sz.nxt >= hp->sz.min);
		hp->sz.nxt = len;
		if (hp->sz.min > (ssize_t)len)
			hp->sz.min = len;
	}

	return (HPACK_RES_OK);
}

enum hpack_result_e
hpack_limit(struct hpack **hpp, size_t len)
{
	struct hpack *hp;
	enum hpack_result_e res;
	size_t mem;

	if (hpp == NULL)
		return (HPACK_RES_ARG);

	hp = *hpp;
	if (hp == NULL || hp->magic != ENCODER_MAGIC)
		return (HPACK_RES_ARG);

	if (hp->ctx.res != HPACK_RES_OK) {
		assert(hp->ctx.res == HPACK_RES_BLK);
		return (HPACK_RES_BSY);
	}

	if (len > UINT16_MAX)
		return (HPACK_RES_LEN); /* the codec is NOT defunct */

	mem = hp->sz.mem;
	if (len >= hp->sz.max && mem < hp->sz.max)
		mem = hp->sz.max;

	res = hpack_realloc(&hp, mem);
	if (res < 0) {
		assert(*hpp == hp);
		if (res != HPACK_RES_REA)
			hp->magic = DEFUNCT_MAGIC;
		return (res);
	}

	*hpp = hp;
	hp->sz.cap = len;
	return (HPACK_RES_OK);
}

enum hpack_result_e
hpack_trim(struct hpack **hpp)
{
	struct hpack *hp;
	size_t max;

	if (hpp == NULL)
		return (HPACK_RES_ARG);

	hp = *hpp;
	if (hp == NULL || hp->alloc.realloc == NULL)
		return (HPACK_RES_ARG);
	if (hp->magic != DECODER_MAGIC && hp->magic != ENCODER_MAGIC)
		return (HPACK_RES_ARG);

	if (hp->ctx.res != HPACK_RES_OK) {
		assert(hp->ctx.res == HPACK_RES_BLK);
		return (HPACK_RES_BSY);
	}

	assert(hp->sz.lim <= (ssize_t) hp->sz.max);
	if (hp->magic == ENCODER_MAGIC)
		max = HPACK_LIMIT(hp);
	else
		max = hp->sz.max;

	if (hp->sz.mem > max) {
		hp = hp->alloc.realloc(hp, sizeof *hp + max, hp->alloc.priv);
		if (hp == NULL)
			return (HPACK_RES_OOM); /* the codec is NOT defunct */
		hp->sz.mem = max;
		*hpp = hp;
	}

	return (HPACK_RES_OK);
}

void
hpack_free(struct hpack **hpp)
{
	struct hpack *hp;

	if (hpp == NULL)
		return;

	hp = *hpp;
	if (hp == NULL)
		return;

	*hpp = NULL;
	if (hp->magic != ENCODER_MAGIC && hp->magic != DECODER_MAGIC &&
	    hp->magic != DEFUNCT_MAGIC)
		return;

	hp->magic = 0;
	if (hp->alloc.free != NULL)
		hp->alloc.free(hp, hp->alloc.priv);
}

/**********************************************************************
 * Tables probing
 */

enum hpack_result_e
hpack_static(hpack_event_f cb, void *priv)
{
	struct hpack_ctx ctx;

	if (cb == NULL)
		return (HPACK_RES_ARG);

	(void)memset(&ctx, 0, sizeof ctx);
	ctx.cb = cb;
	ctx.priv = priv;

	HPT_foreach(&ctx, HPT_FLG_STATIC);
	return (HPACK_RES_OK);
}

static enum hpack_result_e
hpack_foreach(struct hpack *hp, hpack_event_f cb, void *priv, int flg)
{
	struct hpack_ctx *ctx;

	if (hp == NULL || cb == NULL)
		return (HPACK_RES_ARG);
	if (hp->magic != DECODER_MAGIC && hp->magic != ENCODER_MAGIC)
		return (HPACK_RES_ARG);

	ctx = &hp->ctx;

	(void)memset(ctx, 0, sizeof *ctx);
	ctx->hp = hp;
	ctx->cb = cb;
	ctx->priv = priv;

	HPT_foreach(ctx, flg);
	return (HPACK_RES_OK);
}

enum hpack_result_e
hpack_dynamic(struct hpack *hp, hpack_event_f cb, void *priv)
{

	return (hpack_foreach(hp, cb, priv, HPT_FLG_DYNAMIC));
}

enum hpack_result_e
hpack_tables(struct hpack *hp, hpack_event_f cb, void *priv)
{

	return (hpack_foreach(hp, cb, priv, HPT_FLG_STATIC|HPT_FLG_DYNAMIC));
}

enum hpack_result_e
hpack_entry(struct hpack *hp, size_t idx, const char **nam, const char **val)
{
	struct hpt_field hf;
	int retval;

	if (hp == NULL || nam == NULL || val == NULL)
		return (HPACK_RES_ARG);
	if (hp->magic != DECODER_MAGIC && hp->magic != ENCODER_MAGIC)
		return (HPACK_RES_ARG);
	if (idx == 0 || idx > HPACK_STATIC + hp->cnt)
		return (HPACK_RES_IDX);

	retval = HPT_search(&hp->ctx, idx, &hf);
	assert(retval == HPACK_RES_OK);
	*nam = hf.nam;
	*val = hf.val;
	return (retval);
}

/**********************************************************************
 * Errors
 */

const char *
hpack_strerror(enum hpack_result_e res)
{

#define HPR(val, cod, txt, rst)	\
	if (res == cod)		\
		return (txt);
#include "tbl/hpack_tbl.h"
#undef HPR
	return (NULL);
}

static void /* NB: hexdump -C output */
hpack_hexdump(void *ptr, ssize_t len, hpack_dump_f *dump, void *priv)
{
	uint8_t *buf;
	size_t pos;
	int i;

	buf = ptr;
	pos = 0;

	while (len > 0) {
		dump(priv, "\t%06zx: ", pos);
		for (i = 0; i < 16; i++) {
			if (i == 8)
				dump(priv, " ");
			if (i < len)
				dump(priv, "%02x ", buf[i]);
			else
				dump(priv, "   ");
		}
		dump(priv, "| ");
		for (i = 0; i < 16; i++) {
			if (i == 8)
				dump(priv, " ");
			if (i < len)
				dump(priv, "%c",
				    isprint(buf[i]) ? buf[i] : '.');
		}
		dump(priv, "\n");
		len -= 16;
		buf += 16;
		pos += 16;
	}
}

void
hpack_dump(const struct hpack *hp, hpack_dump_f *dump, void *priv)
{
	struct hpt_entry *tbl_ptr;
	const char *magic;

	if (hp == NULL || dump == NULL)
		return;

	tbl_ptr = HPACK_TBL(hp);

	switch (hp->magic) {
	case DECODER_MAGIC: magic = "DECODER"; break;
	case ENCODER_MAGIC: magic = "ENCODER"; break;
	case DEFUNCT_MAGIC: magic = "DEFUNCT"; break;
	default: magic = "UNKNOWN";
	}

	dump(priv, "*hp = %p {\n", (const void *)hp);
	dump(priv, "\t.magic = %08x (%s)\n", hp->magic, magic);
	dump(priv, "\t.alloc = {\n");
	dump(priv, "\t\t.malloc = %p\n", FUNC_PTR(hp->alloc.malloc));
	dump(priv, "\t\t.realloc = %p\n", FUNC_PTR(hp->alloc.realloc));
	dump(priv, "\t\t.free = %p\n", FUNC_PTR(hp->alloc.free));
	dump(priv, "\t}\n");
	dump(priv, "\t.sz = {\n");
	dump(priv, "\t\t.mem = %zu\n", hp->sz.mem);
	dump(priv, "\t\t.max = %zu\n", hp->sz.max);
	dump(priv, "\t\t.lim = %zd\n", hp->sz.lim);
	dump(priv, "\t\t.cap = %zd\n", hp->sz.cap);
	dump(priv, "\t\t.len = %zu\n", hp->sz.len);
	dump(priv, "\t\t.nxt = %zd\n", hp->sz.nxt);
	dump(priv, "\t\t.min = %zd\n", hp->sz.min);
	dump(priv, "\t}\n");
	dump(priv, "\t.state = {\n");
	/* XXX: do when bored */
	dump(priv, "\t}\n");
	dump(priv, "\t.ctx = {\n");
	/* XXX: do when bored */
	dump(priv, "\t}\n");
	dump(priv, "\t.cnt = %zu\n", hp->cnt);

	dump(priv, "\t.tbl = %p <<EOF\n", (void *)tbl_ptr);
	hpack_hexdump(tbl_ptr, hp->sz.len, dump, priv);
	dump(priv, "\tEOF\n");
	dump(priv, "}\n");
}

/**********************************************************************
 * Decoder
 */

static int
hpack_decode_raw_string(HPACK_CTX, size_t len)
{
	struct hpack_state *hs;
	unsigned fit;

	hs = &ctx->hp->state;
	fit = len <= ctx->len;
	if (!fit)
		len = ctx->len;

	CALL(HPD_cat, ctx, (const char *)ctx->ptr.blk, len);
	if (fit)
		CALL(HPD_putc, ctx, '\0');

	ctx->ptr.blk += len;
	ctx->len -= len;
	hs->stt.str.len -= len;
	EXPECT(ctx, BUF, hs->stt.str.len == 0);

	return (0);
}

static int
hpack_decode_string(HPACK_CTX, enum hpack_event_e evt)
{
	struct hpack_state *hs;
	uint16_t len;
	uint8_t huf;

	hs = &ctx->hp->state;

	switch (hs->stp) {
	case HPACK_STP_NAM_LEN:
	case HPACK_STP_VAL_LEN:
		/* decode integer */
		huf = *ctx->ptr.blk & HPACK_PAT_HUF;
		CALL(HPI_decode, ctx, HPACK_PFX_STR, &len);

		/* set up string decoding */
		hs->magic = huf ?  HUF_STATE_MAGIC : STR_STATE_MAGIC;
		hs->stt.str.len = len;
		hs->stp++;

		if (huf) {
			hs->stt.str.dec = NULL;
			hs->stt.str.oct = NULL;
			hs->stt.str.blen = 0;
			hs->stt.str.bits = 0;
		}

		if (evt == HPACK_EVT_NAME)
			EXPECT(ctx, LEN, len > 0);

		if (len > 0)
			EXPECT(ctx, BUF, ctx->len > 0);

		/* fall through */
	case HPACK_STP_NAM_STR:
	case HPACK_STP_VAL_STR:
		break;
	default:
		WRONG("Unknown step");
	}

	assert(hs->stt.str.len > 0 || evt != HPACK_EVT_NAME);

	if (hs->magic == HUF_STATE_MAGIC)
		CALL(HPH_decode, ctx, hs->stt.str.len);
	else {
		assert(hs->magic == STR_STATE_MAGIC);
		CALL(hpack_decode_raw_string, ctx, hs->stt.str.len);
	}

	return (0);
}

static int
hpack_decode_field(HPACK_CTX)
{

	switch (ctx->hp->state.stp) {
	case HPACK_STP_FLD_INT:
		ctx->hp->state.stp = HPACK_STP_NAM_LEN;
		ctx->fld.nam = ctx->buf;
		/* fall through */
	case HPACK_STP_NAM_LEN:
	case HPACK_STP_NAM_STR:
		if (ctx->hp->state.idx == 0)
			CALL(hpack_decode_string, ctx, HPACK_EVT_NAME);
		else
			CALL(HPT_decode_name, ctx);
		ctx->hp->state.stp = HPACK_STP_VAL_LEN;
		ctx->fld.nam_sz = ctx->buf - ctx->fld.nam - 1;
		CALL(HPV_token, ctx, ctx->fld.nam, ctx->fld.nam_sz);
		ctx->fld.val = ctx->buf;
		/* fall through */
	case HPACK_STP_VAL_LEN:
	case HPACK_STP_VAL_STR:
		CALL(hpack_decode_string, ctx, HPACK_EVT_VALUE);
		ctx->fld.val_sz = ctx->buf - ctx->fld.val - 1;
		CALL(HPV_value, ctx, ctx->fld.val, ctx->fld.val_sz);
		HPD_notify(ctx);
		ctx->hp->state.stp = HPACK_STP_FLD_INT;
		break;
	default:
		WRONG("Unknown step");
	}

	return (0);
}

static int
hpack_decode_indexed(HPACK_CTX)
{
	uint16_t idx;

	CALL(HPI_decode, ctx, HPACK_PFX_IDX, &idx);
	CALLBACK(ctx, HPACK_EVT_FIELD, NULL, idx);
	return (HPT_decode(ctx, idx));
}

static int
hpack_decode_dynamic(HPACK_CTX)
{

	if (ctx->hp->state.stp == HPACK_STP_FLD_INT) {
		CALL(HPI_decode, ctx, HPACK_PFX_DYN, &ctx->hp->state.idx);
		CALLBACK(ctx, HPACK_EVT_FIELD, NULL, 0);
	}
	CALL(hpack_decode_field, ctx);
	HPT_index(ctx);
	return (0);
}

static int
hpack_decode_literal(HPACK_CTX)
{

	if (ctx->hp->state.stp == HPACK_STP_FLD_INT) {
		CALL(HPI_decode, ctx, HPACK_PFX_LIT, &ctx->hp->state.idx);
		CALLBACK(ctx, HPACK_EVT_FIELD, NULL, 0);
	}
	return (hpack_decode_field(ctx));
}

static int
hpack_decode_never(HPACK_CTX)
{

	if (ctx->hp->state.stp == HPACK_STP_FLD_INT) {
		CALL(HPI_decode, ctx, HPACK_PFX_NVR, &ctx->hp->state.idx);
		CALLBACK(ctx, HPACK_EVT_FIELD, NULL, 0);
		CALLBACK(ctx, HPACK_EVT_NEVER, NULL, 0);
	}
	return (hpack_decode_field(ctx));
}

static int
hpack_decode_update(HPACK_CTX)
{
	uint16_t sz;

	EXPECT(ctx, UPD, ctx->can_upd);

	CALL(HPI_decode, ctx, HPACK_PFX_UPD, &sz);
	if (ctx->hp->sz.min >= 0) {
		assert(ctx->hp->sz.min <= ctx->hp->sz.nxt);
		if (ctx->hp->sz.min < ctx->hp->sz.nxt) {
			EXPECT(ctx, UPD, sz == ctx->hp->sz.min);
			ctx->hp->sz.min = ctx->hp->sz.nxt;
		}
		else {
			EXPECT(ctx, UPD, sz == ctx->hp->sz.nxt ||
			    sz < ctx->hp->sz.nxt);
			ctx->hp->sz.max = ctx->hp->sz.nxt;
			ctx->hp->sz.lim = sz;
			ctx->hp->sz.min = -1;
			ctx->hp->sz.nxt = -1;
			ctx->can_upd = 0;
		}
	}
	else
		ctx->can_upd = 0;
	EXPECT(ctx, LEN, sz <= ctx->hp->sz.max);
	ctx->hp->sz.lim = sz;
	HPT_adjust(ctx, ctx->hp->sz.len);
	CALLBACK(ctx, HPACK_EVT_TABLE, NULL, sz);
	return (0);
}

static inline unsigned
hpack_check_buffer(struct hpack_ctx *ctx, const struct hpack_decoding *dec)
{
	char *dec_buf = dec->buf;

	return (dec_buf + dec->buf_len == ctx->buf + ctx->buf_len);
}

enum hpack_result_e
hpack_decode(struct hpack *hp, const struct hpack_decoding *dec)
{
	struct hpack_ctx *ctx;
	int retval;

	if (hp == NULL || hp->magic != DECODER_MAGIC || dec == NULL ||
	    dec->blk == NULL || dec->blk_len == 0 || dec->buf == NULL ||
	    dec->buf_len == 0 || dec->cb == NULL)
		return (HPACK_RES_ARG);

	ctx = &hp->ctx;
	assert(ctx->hp == hp);

	if (ctx->res == HPACK_RES_BLK) {
		assert(ctx->buf != NULL);
		EXPECT(ctx, ARG, hpack_check_buffer(ctx, dec));
	}
	else {
		assert(ctx->res == HPACK_RES_OK);
		ctx->buf = dec->buf;
		ctx->buf_len = dec->buf_len;
		ctx->can_upd = 1;
		hp->state.stp = HPACK_STP_FLD_INT;
	}

	ctx->arg.dec = dec;
	ctx->ptr.blk = dec->blk;
	ctx->len = dec->blk_len;
	ctx->cb = dec->cb;
	ctx->priv = dec->priv;
	ctx->res = dec->cut ? HPACK_RES_BLK : HPACK_RES_OK;

	while (ctx->len > 0) {
		if (!hp->state.bsy && hp->state.stp == HPACK_STP_FLD_INT)
			hp->state.typ = *ctx->ptr.blk;
		if ((hp->state.typ & HPACK_PAT_UPD) != HPACK_PAT_UPD) {
			if (hp->sz.nxt >= 0) {
				hp->magic = DEFUNCT_MAGIC;
				return (HPACK_RES_RSZ);
			}
			assert(hp->sz.min < 0);
			ctx->can_upd = 0;
		}
#define HPACK_DECODE(l, U, or)						\
		if ((hp->state.typ & HPACK_PAT_##U) == HPACK_PAT_##U)	\
			retval = hpack_decode_##l(ctx);			\
		or
		HPACK_DECODE(indexed, IDX, else)
		HPACK_DECODE(dynamic, DYN, else)
		HPACK_DECODE(update,  UPD, else)
		HPACK_DECODE(never,   NVR, else)
		HPACK_DECODE(literal, LIT, OUT_OF_BITS)
#undef HPACK_DECODE
		if (retval != 0) {
			assert(ctx->res != HPACK_RES_OK);
			if (dec->cut && ctx->res == HPACK_RES_BUF)
				ctx->res = HPACK_RES_BLK;
			else
				hp->magic = DEFUNCT_MAGIC;
			return (ctx->res);
		}
	}

	assert(ctx->res == HPACK_RES_OK || ctx->res == HPACK_RES_BLK);
	return (ctx->res);
}

static void
hpack_assert_cb(enum hpack_event_e evt, const char *buf, size_t len, void *priv)
{

#ifdef NDEBUG
	(void)evt;
	(void)buf;
	(void)len;
#endif
	(void)priv;

	switch (evt) {
	case HPACK_EVT_FIELD:
		assert(buf == NULL);
		break;
	case HPACK_EVT_EVICT:
		assert(buf == NULL);
		assert(len > 0);
		break;
	case HPACK_EVT_INDEX:
		assert(buf == NULL);
		assert(len > HPACK_OVERHEAD);
		break;
	case HPACK_EVT_NEVER:
		assert(len == 0);
		/* fall through */
	case HPACK_EVT_TABLE:
		assert(buf == NULL);
		break;
	case HPACK_EVT_VALUE:
	case HPACK_EVT_NAME:
		assert(buf != NULL);
		assert(len == strlen(buf));
		break;
	default:
		WRONG("Unknown event");
	}
}

enum hpack_result_e
hpack_decode_fields(struct hpack *hp, const struct hpack_decoding *dec,
    const char **pnam, const char **pval)
{
	struct hpack_decoding fld_dec;
	struct hpack_ctx *ctx;
	const char *nam, *val;
	int retval;

	if (hp == NULL || hp->magic != DECODER_MAGIC || dec == NULL ||
	    pnam == NULL || pval == NULL)
		return (HPACK_RES_ARG);

	nam = *pnam;
	val = *pval;
	if ((nam == NULL) ^ (val == NULL))
		return (HPACK_RES_ARG);

	ctx = &hp->ctx;
	assert(ctx->hp == hp);
	if (nam == NULL && ctx->res != HPACK_RES_OK &&
	    ctx->res != HPACK_RES_BLK) {
		hp->magic = DEFUNCT_MAGIC;
		return (HPACK_RES_ARG);
	}

	if (nam == NULL) {
		memcpy(&fld_dec, dec, sizeof fld_dec);
		fld_dec.cb = hpack_assert_cb;
		retval = hpack_decode(hp, &fld_dec);
		if (retval != HPACK_RES_OK)
			return (retval);
		ctx->res = HPACK_RES_FLD;
	}

	assert(ctx->res == HPACK_RES_FLD);

	if (nam == NULL) {
		nam = dec->buf;
		assert(val == NULL);
	}
	else {
		nam = val + strlen(val) + 1;
		assert(hpack_check_buffer(ctx, dec));
	}

	if (nam == ctx->buf) {
		nam = NULL;
		val = NULL;
		ctx->res = HPACK_RES_OK;
	}
	else {
		val = nam + strlen(nam) + 1;
		assert(nam < ctx->buf);
		assert(val < ctx->buf);
	}

	*pnam = nam;
	*pval = val;

	return (ctx->res);
}

/**********************************************************************
 * Encoder
 */

static int
hpack_encode_string(HPACK_CTX, HPACK_FLD, enum hpack_event_e evt)
{
	const char *str;
	size_t len;
	unsigned huf;
	hpack_validate_f *val;

	if (evt == HPACK_EVT_NAME) {
		assert(~fld->flg & HPACK_FLG_NAM_IDX);
		str = fld->nam;
		huf = fld->flg & HPACK_FLG_NAM_HUF;
		val = HPV_token;
	}
	else {
		str = fld->val;
		huf = fld->flg & HPACK_FLG_VAL_HUF;
		val = HPV_value;
	}

	len = strlen(str);
	CALL(val, ctx, str, len);

	if (huf != 0) {
		HPH_size(str, &len);
		HPI_encode(ctx, HPACK_PFX_HUF, HPACK_PAT_HUF, len);
		HPH_encode(ctx, str);
	}
	else {
		HPI_encode(ctx, HPACK_PFX_STR, HPACK_PAT_STR, len);
		HPE_bcat(ctx, str, len);
	}

	return (0);
}

static int
hpack_encode_field(HPACK_CTX, HPACK_FLD, enum hpi_pattern_e pat, size_t pfx)
{
	uint16_t idx;

	if (fld->flg & HPACK_FLG_NAM_IDX) {
		idx = fld->nam_idx;
		EXPECT(ctx, IDX, idx > 0 &&
		    idx <= ctx->hp->cnt + HPACK_STATIC);
	}
	else
		idx = 0;

	HPI_encode(ctx, pfx, pat, idx);

	if (idx == 0)
		CALL(hpack_encode_string, ctx, fld, HPACK_EVT_NAME);

	return (hpack_encode_string(ctx, fld, HPACK_EVT_VALUE));
}

static int
hpack_encode_indexed(HPACK_CTX, HPACK_FLD)
{

	EXPECT(ctx, IDX, fld->idx > 0 &&
	    fld->idx <= ctx->hp->cnt + HPACK_STATIC);

	HPI_encode(ctx, HPACK_PFX_IDX, HPACK_PAT_IDX, fld->idx);
	return (0);
}

static int
hpack_encode_dynamic(HPACK_CTX, HPACK_FLD)
{
	struct hpt_field hf;

	CALL(hpack_encode_field, ctx, fld, HPACK_PAT_DYN, HPACK_PFX_DYN);
	if (fld->flg & HPACK_FLG_NAM_IDX) {
		(void)HPT_search(ctx, fld->nam_idx, &hf);
		assert(ctx->res == HPACK_RES_BLK);
		ctx->fld.nam = hf.nam;
		ctx->fld.nam_sz = hf.nam_sz;
	}
	else {
		ctx->fld.nam = fld->nam;
		ctx->fld.nam_sz = strlen(fld->nam);
	}
	ctx->fld.val = fld->val;
	ctx->fld.val_sz = strlen(fld->val);
	HPT_index(ctx);

	return (0);
}

static int
hpack_encode_literal(HPACK_CTX, HPACK_FLD)
{

	return (hpack_encode_field(ctx, fld, HPACK_PAT_LIT, HPACK_PFX_LIT));
}

static int
hpack_encode_never(HPACK_CTX, HPACK_FLD)
{

	return (hpack_encode_field(ctx, fld, HPACK_PAT_NVR, HPACK_PFX_NVR));
}

static size_t
hpack_cap(struct hpack *hp, size_t lim, ssize_t max)
{

	if (hp->sz.cap < 0)
		return (lim);

	if (hp->sz.cap > max) {
		hp->sz.lim = -1;
		return (lim);
	}

	hp->sz.lim = hp->sz.cap;
	return (hp->sz.lim);
}

static int
hpack_encode_update(HPACK_CTX, size_t lim)
{
	struct hpack *hp;

	assert(ctx->can_upd);
	assert(lim <= UINT16_MAX);

	hp = ctx->hp;

	if (hp->sz.min >= 0) {
		assert(hp->sz.min <= hp->sz.nxt);
		hp->sz.max = lim;
		if (hp->sz.min < hp->sz.nxt)
			assert(lim == (size_t)hp->sz.min);
		else
			lim = hpack_cap(hp, lim, hp->sz.nxt);
	}
	else {
		lim = hpack_cap(hp, lim, hp->sz.max);
		assert(lim == (size_t)hp->sz.lim);
	}

	HPT_adjust(ctx, hp->sz.len);
	HPI_encode(ctx, HPACK_PFX_UPD, HPACK_PAT_UPD, lim);
	CALLBACK(ctx, HPACK_EVT_TABLE, NULL, lim);

	if (hp->sz.min < hp->sz.nxt) {
		assert(hp->sz.min >= 0);
		hp->sz.min = hp->sz.nxt;
	}
	else if (hp->sz.min >= 0) {
		assert(hp->sz.min == hp->sz.nxt);
		hp->sz.min = -1;
		hp->sz.nxt = -1;
		ctx->can_upd = 0;
	}

	assert(lim <= hp->sz.max);
	return (0);
}

enum hpack_result_e
hpack_encode(struct hpack *hp, const struct hpack_encoding *enc)
{
	const struct hpack_field *fld;
	struct hpack_ctx *ctx;
	size_t cnt;
	int retval;

	if (hp == NULL || hp->magic != ENCODER_MAGIC || enc == NULL ||
	    enc->fld == NULL || enc->fld_cnt == 0 || enc->buf == NULL ||
	    enc->buf_len == 0 || enc->cb == NULL)
		return (HPACK_RES_ARG);

	ctx = &hp->ctx;
	assert(ctx->hp == hp);

	if (ctx->res == HPACK_RES_BLK) {
		assert(ctx->hp == hp);
	}
	else {
		assert(ctx->res == HPACK_RES_OK);
		ctx->can_upd = 1;
		ctx->res = HPACK_RES_BLK;
	}

	ctx->arg.enc = enc;
	ctx->ptr.cur = enc->buf;
	ctx->len = 0;
	ctx->cb = enc->cb;
	ctx->priv = enc->priv;

	if (ctx->can_upd && hp->sz.min >= 0) {
		assert(hp->sz.min <= hp->sz.nxt);
		retval = hpack_encode_update(ctx, hp->sz.min);
		assert(retval == 0);
		assert(hp->sz.min == hp->sz.nxt);
		if (hp->sz.nxt >= 0) {
			retval = hpack_encode_update(ctx, hp->sz.nxt);
			assert(retval == 0);
		}
		assert(!ctx->can_upd);
	}

	if (ctx->can_upd && ctx->hp->sz.cap >= 0) {
		assert(ctx->hp->sz.lim == -1);
		if ((size_t)ctx->hp->sz.cap < ctx->hp->sz.max) {
			retval = hpack_encode_update(ctx, hp->sz.cap);
			assert(retval == 0);
			hp->sz.cap = -1;
		}
	}

	ctx->can_upd = 0;
	cnt = enc->fld_cnt;
	fld = enc->fld;

	while (cnt > 0) {
		CALLBACK(ctx, HPACK_EVT_FIELD, NULL, 0);
		switch (fld->flg & HPACK_FLG_TYP_MSK) {
#define HPACK_ENCODE(l, U)					\
		case HPACK_FLG_TYP_##U:				\
			retval = hpack_encode_##l(ctx, fld);	\
			break;
		HPACK_ENCODE(indexed, IDX)
		HPACK_ENCODE(dynamic, DYN)
		HPACK_ENCODE(never,   NVR)
		HPACK_ENCODE(literal, LIT)
#undef HPACK_ENCODE
		default:
			hp->magic = DEFUNCT_MAGIC;
			return (HPACK_RES_ARG);
		}
		if (retval != 0) {
			assert(ctx->res != HPACK_RES_OK);
			assert(ctx->res != HPACK_RES_BLK);
			hp->magic = DEFUNCT_MAGIC;
			return (ctx->res);
		}
		fld++;
		cnt--;
	}

	HPE_send(ctx);

	assert(ctx->res == HPACK_RES_BLK);
	if (!enc->cut)
		ctx->res = HPACK_RES_OK;

	return (ctx->res);
}

enum hpack_result_e
hpack_clean_field(struct hpack_field *fld)
{

	if (fld == NULL)
		return (HPACK_RES_ARG);

	switch (fld->flg & HPACK_FLG_TYP_MSK) {
	case HPACK_FLG_TYP_IDX:
		fld->idx = 0;
		break;
	case HPACK_FLG_TYP_DYN:
	case HPACK_FLG_TYP_LIT:
	case HPACK_FLG_TYP_NVR:
		if (fld->flg & HPACK_FLG_NAM_IDX) {
			fld->nam_idx = 0;
			fld->flg &= ~HPACK_FLG_NAM_IDX;
		}
		else
			fld->nam = NULL;
		fld->val = NULL;
		fld->flg &= ~HPACK_FLG_NAM_HUF;
		fld->flg &= ~HPACK_FLG_VAL_HUF;
		break;
	default:
		return (HPACK_RES_ARG);
	}

	fld->flg &= ~HPACK_FLG_TYP_MSK;

	if (fld->nam != NULL || fld->val != NULL || fld->flg != 0)
		return (HPACK_RES_ARG);

	assert(fld->idx == 0);
	assert(fld->nam_idx == 0);

	return (HPACK_RES_OK);
}
