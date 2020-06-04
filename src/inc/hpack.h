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

/* hpack_result */
enum hpack_result_e {
	HPACK_RES_FLD = 2,
	HPACK_RES_BLK = 1,
	HPACK_RES_OK = 0,
	HPACK_RES_ARG = -1,
	HPACK_RES_BUF = -2,
	HPACK_RES_INT = -3,
	HPACK_RES_IDX = -4,
	HPACK_RES_LEN = -5,
	HPACK_RES_HUF = -6,
	HPACK_RES_CHR = -7,
	HPACK_RES_UPD = -8,
	HPACK_RES_RSZ = -9,
	HPACK_RES_OOM = -10,
	HPACK_RES_BSY = -11,
	HPACK_RES_BIG = -12,
	HPACK_RES_HDR = -13,
	HPACK_RES_REA = -14,
};

/* hpack_alloc */
struct hpack;
typedef void * hpack_malloc_f (size_t, void *);
typedef void * hpack_realloc_f (void *, size_t, void *);
typedef void hpack_free_f (void *, void *);

struct hpack_alloc {
	hpack_malloc_f	   *malloc;
	hpack_realloc_f	   *realloc;
	hpack_free_f	   *free;
	void		   *priv;
};

extern const struct hpack_alloc *hpack_default_alloc;
struct hpack * hpack_decoder(size_t, ssize_t, const struct hpack_alloc *);
struct hpack * hpack_encoder(size_t, ssize_t, const struct hpack_alloc *);
void hpack_free(struct hpack **);
enum hpack_result_e hpack_resize(struct hpack **, size_t);
enum hpack_result_e hpack_limit(struct hpack **, size_t);
enum hpack_result_e hpack_trim(struct hpack **);

/* hpack_error */
typedef void hpack_dump_f (void *, const char *, ...);

const char * hpack_strerror(enum hpack_result_e);
void hpack_dump(const struct hpack *, hpack_dump_f *, void *);

/* hpack_event */
enum hpack_event_e {
	HPACK_EVT_FIELD = 0,
	HPACK_EVT_NEVER = 1,
	HPACK_EVT_INDEX = 2,
	HPACK_EVT_NAME = 3,
	HPACK_EVT_VALUE = 4,
	HPACK_EVT_DATA = 5,
	HPACK_EVT_EVICT = 6,
	HPACK_EVT_TABLE = 7,
};

typedef void hpack_event_f (enum hpack_event_e, const char *, size_t,
    void *);

/* hpack_decode */
struct hpack_decoding {
	const void	 *blk;
	size_t		 blk_len;
	void		 *buf;
	size_t		 buf_len;
	hpack_event_f	 *cb;
	void		 *priv;
	unsigned	 cut;
};

enum hpack_result_e hpack_decode(struct hpack *,
    const struct hpack_decoding *);
enum hpack_result_e hpack_decode_fields(struct hpack *,
    const struct hpack_decoding *, const char **, const char **);

/* hpack_encode */
enum hpack_flag_e {
	HPACK_FLG_TYP_IDX = 0x01,
	HPACK_FLG_TYP_DYN = 0x02,
	HPACK_FLG_TYP_LIT = 0x04,
	HPACK_FLG_TYP_NVR = 0x08,
	HPACK_FLG_TYP_MSK = 0x0f,
	HPACK_FLG_NAM_IDX = 0x10,
	HPACK_FLG_NAM_HUF = 0x20,
	HPACK_FLG_VAL_HUF = 0x40,
};

struct hpack_field {
	uint32_t      flg;
	uint16_t      idx;
	uint16_t      nam_idx;
	const char    *nam;
	const char    *val;
};

struct hpack_encoding {
	const struct hpack_field    *fld;
	size_t			    fld_cnt;
	void			    *buf;
	size_t			    buf_len;
	hpack_event_f		    *cb;
	void			    *priv;
	unsigned		    cut;
};

enum hpack_result_e hpack_encode(struct hpack *,
    const struct hpack_encoding *);
enum hpack_result_e hpack_clean_field(struct hpack_field *);

/* hpack_index */
#define HPACK_STATIC 61
#define HPACK_OVERHEAD 32
enum hpack_result_e hpack_static(hpack_event_f, void *);
enum hpack_result_e hpack_dynamic(struct hpack *, hpack_event_f, void *);
enum hpack_result_e hpack_tables(struct hpack *, hpack_event_f, void *);
enum hpack_result_e hpack_entry(struct hpack *, size_t, const char **,
    const char **);
