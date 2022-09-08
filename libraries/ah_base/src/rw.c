// SPDX-License-Identifier: EPL-2.0

#include "ah/rw.h"

#include "ah/assert.h"
#include "ah/buf.h"
#include "ah/err.h"

#include <string.h>

ah_extern ah_rw_t ah_rw_from_writable(void* base, size_t size)
{
    ah_assert_if_debug(base != NULL || size == 0u);

    return (ah_rw_t) {
        .r = &((uint8_t*) base)[0u],
        .w = &((uint8_t*) base)[0u],
        .e = &((uint8_t*) base)[size],
    };
}

ah_extern ah_rw_t ah_rw_from_writable_buf(ah_buf_t* buf)
{
    if (ah_unlikely(buf == NULL)) {
        return (ah_rw_t) { 0u };
    }
    return ah_rw_from_writable(buf->base, buf->size);
}

ah_extern ah_rw_t ah_rw_from_readable(const void* base, size_t size)
{
    ah_assert_if_debug(base != NULL || size == 0u);

    return (ah_rw_t) {
        .r = &((uint8_t*) base)[0u],
        .w = &((uint8_t*) base)[size],
        .e = &((uint8_t*) base)[size],
    };
}

ah_extern ah_rw_t ah_rw_from_readable_buf(const ah_buf_t* buf)
{
    if (ah_unlikely(buf == NULL)) {
        return (ah_rw_t) { 0u };
    }
    return ah_rw_from_readable(buf->base, buf->size);
}

ah_extern ah_buf_t ah_rw_get_readable_as_buf(const ah_rw_t* rw)
{
    if (ah_unlikely(rw == NULL)) {
        return (ah_buf_t) { 0u };
    }

    ah_buf_t buf;
    if (ah_buf_init(&buf, rw->r, (size_t) (rw->w - rw->r)) != AH_ENONE) {
        return ah_buf_from(rw->r, UINT32_MAX);
    }
    return buf;
}

ah_extern size_t ah_rw_get_readable_size(const ah_rw_t* rw)
{
    if (ah_unlikely(rw == NULL)) {
        return 0u;
    }
    return (size_t) (rw->w - rw->r);
}

ah_extern ah_buf_t ah_rw_get_writable_as_buf(const ah_rw_t* rw)
{
    if (ah_unlikely(rw == NULL)) {
        return (ah_buf_t) { 0u };
    }

    ah_buf_t buf;
    if (ah_buf_init(&buf, rw->w, (size_t) (rw->e - rw->w)) != AH_ENONE) {
        return ah_buf_from(rw->w, UINT32_MAX);
    }
    return buf;
}

ah_extern size_t ah_rw_get_writable_size(const ah_rw_t* rw)
{
    if (ah_unlikely(rw == NULL)) {
        return 0u;
    }
    return (size_t) (rw->e - rw->w);
}

ah_extern bool ah_rw_is_readable(const ah_rw_t* rw)
{
    return ah_unlikely(rw != NULL) && rw->r < rw->w;
}

ah_extern bool ah_rw_is_writable(const ah_rw_t* rw)
{
    return ah_unlikely(rw != NULL) && rw->w < rw->e;
}

ah_extern bool ah_rw_copy1(ah_rw_t* src, ah_rw_t* dst)
{
    if (ah_unlikely(src == NULL || dst == NULL)) {
        return false;
    }

    if (ah_unlikely(src->w == src->r)) {
        return false;
    }

    if (ah_unlikely(dst->e == dst->w)) {
        return false;
    }

    *dst->w = *src->r;
    src->r = &src->r[1u];
    dst->w = &dst->w[1u];

    return true;
}

ah_extern bool ah_rw_copyn(ah_rw_t* src, ah_rw_t* dst, size_t n)
{
    if (ah_unlikely(src == NULL || dst == NULL)) {
        return false;
    }

    if (ah_unlikely((size_t) (src->w - src->r) < n)) {
        return false;
    }

    if (ah_unlikely((size_t) (dst->e - dst->w) < n)) {
        return false;
    }

    memcpy(dst->w, src->r, n);
    src->r = &src->r[n];
    dst->w = &dst->w[n];

    return true;
}

ah_extern bool ah_rw_peek1(ah_rw_t* rw, uint8_t* dst)
{
    if (ah_unlikely(rw == NULL || dst == NULL)) {
        return false;
    }

    if (ah_unlikely(rw->r == rw->w)) {
        return false;
    }

    *dst = *rw->r;

    return true;
}

ah_extern bool ah_rw_peekn(ah_rw_t* rw, uint8_t* dst, size_t n)
{
    if (ah_unlikely(rw == NULL || dst == NULL)) {
        return false;
    }

    if (ah_unlikely((size_t) (rw->w - rw->r) < n)) {
        return false;
    }

    memcpy(dst, rw->r, n);

    return true;
}

ah_extern bool ah_rw_read1(ah_rw_t* rw, uint8_t* dst)
{
    if (ah_unlikely(rw == NULL || dst == NULL)) {
        return false;
    }

    if (ah_unlikely(rw->r == rw->w)) {
        return false;
    }

    *dst = *rw->r;
    rw->r = &rw->r[1u];

    return true;
}

ah_extern bool ah_rw_readn(ah_rw_t* rw, uint8_t* dst, size_t n)
{
    if (ah_unlikely(rw == NULL || dst == NULL)) {
        return false;
    }

    if (ah_unlikely((size_t) (rw->w - rw->r) < n)) {
        return false;
    }

    memcpy(dst, rw->r, n);
    rw->r = &rw->r[n];

    return true;
}

ah_extern bool ah_rw_skip1(ah_rw_t* rw)
{
    if (ah_unlikely(rw == NULL)) {
        return false;
    }

    if (ah_unlikely(rw->w == rw->r)) {
        return false;
    }

    rw->r = &rw->r[1u];

    return true;
}

ah_extern bool ah_rw_skipn(ah_rw_t* rw, size_t n)
{
    if (ah_unlikely(rw == NULL)) {
        return false;
    }

    if (ah_unlikely((size_t) (rw->w - rw->r) < n)) {
        return false;
    }

    rw->r = &rw->r[n];

    return true;
}

ah_extern void ah_rw_skip_all(ah_rw_t* rw)
{
    if (ah_likely(rw != NULL)) {
        rw->r = rw->e;
    }
}

ah_extern bool ah_rw_write1(ah_rw_t* rw, uint8_t byte)
{
    if (ah_unlikely(rw == NULL)) {
        return false;
    }

    if (ah_unlikely(rw->w == rw->e)) {
        return false;
    }

    *rw->w = byte;
    rw->w = &rw->w[1u];

    return true;
}

ah_extern bool ah_rw_writen(ah_rw_t* rw, uint8_t* src, size_t n)
{
    if (ah_unlikely(rw == NULL || (src == NULL && n > 0u))) {
        return false;
    }

    if (ah_unlikely((size_t) (rw->e - rw->w) < n)) {
        return false;
    }

    memcpy(rw->w, src, n);
    rw->w = &rw->w[n];

    return true;
}

ah_extern bool ah_rw_juke1(ah_rw_t* rw)
{
    if (ah_unlikely(rw == NULL)) {
        return false;
    }

    if (ah_unlikely(rw->w == rw->e)) {
        return false;
    }

    rw->w = &rw->w[1u];

    return true;
}

ah_extern bool ah_rw_juken(ah_rw_t* rw, size_t n)
{
    if (ah_unlikely(rw == NULL)) {
        return false;
    }

    if (ah_unlikely((size_t) (rw->e - rw->w) < n)) {
        return false;
    }

    rw->w = &rw->w[n];

    return true;
}
