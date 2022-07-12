// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/rw.h"

#include "ah/assert.h"
#include "ah/buf.h"
#include "ah/err.h"

#include <string.h>

ah_extern ah_rw_t ah_rw_from_writable(void* base, size_t size)
{
    return (ah_rw_t) {
        .r = &((uint8_t*) base)[0u],
        .w = &((uint8_t*) base)[0u],
        .e = &((uint8_t*) base)[size],
    };
}

ah_extern ah_rw_t ah_rw_from_writable_buf(ah_buf_t* buf)
{
    ah_assert(buf != NULL);

    return ah_rw_from_writable(buf->base, buf->size);
}

ah_extern ah_rw_t ah_rw_from_readable(const void* base, size_t size)
{
    return (ah_rw_t) {
        .r = &((uint8_t*) base)[0u],
        .w = &((uint8_t*) base)[size],
        .e = &((uint8_t*) base)[size],
    };
}

ah_extern ah_rw_t ah_rw_from_readable_buf(const ah_buf_t* buf)
{
    ah_assert(buf != NULL);

    return ah_rw_from_readable(buf->base, buf->size);
}

ah_extern ah_buf_t ah_rw_get_readable_as_buf(const ah_rw_t* rw)
{
    ah_assert(rw != NULL);

    ah_buf_t buf;
    if (ah_buf_init(&buf, rw->r, (size_t) (rw->w - rw->r)) != AH_ENONE) {
        return ah_buf_from(rw->r, UINT32_MAX);
    }
    return buf;
}

ah_extern size_t ah_rw_get_readable_size(const ah_rw_t* rw)
{
    ah_assert(rw != NULL);

    return (size_t) (rw->w - rw->r);
}

ah_extern ah_buf_t ah_rw_get_writable_as_buf(const ah_rw_t* rw)
{
    ah_assert(rw != NULL);

    ah_buf_t buf;
    if (ah_buf_init(&buf, rw->w, (size_t) (rw->e - rw->w)) != AH_ENONE) {
        return ah_buf_from(rw->w, UINT32_MAX);
    }
    return buf;
}

ah_extern size_t ah_rw_get_writable_size(const ah_rw_t* rw)
{
    ah_assert(rw != NULL);

    return (size_t) (rw->e - rw->w);
}

ah_extern bool ah_rw_is_containing_buf(const ah_rw_t* rw, const ah_buf_t* buf)
{
    ah_assert(rw != NULL);
    ah_assert(buf != NULL);

    return rw->r <= buf->base && rw->e >= &buf->base[buf->size];
}

ah_extern bool ah_rw_is_readable(const ah_rw_t* rw)
{
    ah_assert(rw != NULL);

    return rw->r < rw->w;
}

ah_extern bool ah_rw_is_writable(const ah_rw_t* rw)
{
    ah_assert(rw != NULL);

    return rw->w < rw->e;
}

ah_extern bool ah_rw_copy1(ah_rw_t* src, ah_rw_t* dst)
{
    ah_assert(src != NULL);
    ah_assert(dst != NULL);

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

ah_extern bool ah_rw_copyn(ah_rw_t* src, ah_rw_t* dst, size_t size)
{
    ah_assert(src != NULL);
    ah_assert(dst != NULL);

    if (ah_unlikely((size_t) (src->w - src->r) < size)) {
        return false;
    }

    if (ah_unlikely((size_t) (dst->e - dst->w) < size)) {
        return false;
    }

    memcpy(dst->w, src->r, size);
    src->r = &src->r[size];
    dst->w = &dst->w[size];

    return true;
}

ah_extern bool ah_rw_peek1(ah_rw_t* rw, uint8_t* dst)
{
    ah_assert(rw != NULL);

    if (ah_unlikely(rw->r == rw->w)) {
        return false;
    }

    *dst = *rw->r;

    return true;
}

ah_extern bool ah_rw_peekn(ah_rw_t* rw, uint8_t* dst, size_t size)
{
    ah_assert(rw != NULL);
    ah_assert(dst != NULL);

    if (ah_unlikely((size_t) (rw->w - rw->r) < size)) {
        return false;
    }

    memcpy(dst, rw->r, size);

    return true;
}

ah_extern bool ah_rw_read1(ah_rw_t* rw, uint8_t* dst)
{
    ah_assert(rw != NULL);

    if (ah_unlikely(rw->r == rw->w)) {
        return false;
    }

    *dst = *rw->r;
    rw->r = &rw->r[1u];

    return true;
}

ah_extern bool ah_rw_readn(ah_rw_t* rw, uint8_t* dst, size_t size)
{
    ah_assert(rw != NULL);
    ah_assert(dst != NULL);

    if (ah_unlikely((size_t) (rw->w - rw->r) < size)) {
        return false;
    }

    memcpy(dst, rw->r, size);
    rw->r = &rw->r[size];

    return true;
}

ah_extern bool ah_rw_skip1(ah_rw_t* rw)
{
    ah_assert(rw != NULL);

    if (ah_unlikely(rw->w == rw->r)) {
        return false;
    }

    rw->r = &rw->r[1u];

    return true;
}

ah_extern bool ah_rw_skipn(ah_rw_t* rw, size_t size)
{
    ah_assert(rw != NULL);

    if (ah_unlikely((size_t) (rw->w - rw->r) < size)) {
        return false;
    }

    rw->r = &rw->r[size];

    return true;
}

ah_extern void ah_rw_skip_all(ah_rw_t* rw)
{
    ah_assert(rw != NULL);

    rw->r = rw->e;
}

ah_extern bool ah_rw_write1(ah_rw_t* rw, uint8_t byte)
{
    ah_assert(rw != NULL);

    if (ah_unlikely(rw->w == rw->e)) {
        return false;
    }

    *rw->w = byte;
    rw->w = &rw->w[1u];

    return true;
}

ah_extern bool ah_rw_writen(ah_rw_t* rw, uint8_t* src, size_t size)
{
    ah_assert(rw != NULL);
    ah_assert(src != NULL);

    if (ah_unlikely((size_t) (rw->e - rw->w) < size)) {
        return false;
    }

    memcpy(rw->w, src, size);
    rw->w = &rw->w[size];

    return true;
}

ah_extern bool ah_rw_juke1(ah_rw_t* rw)
{
    ah_assert(rw != NULL);

    if (ah_unlikely(rw->w == rw->e)) {
        return false;
    }

    rw->w = &rw->w[1u];

    return true;
}

ah_extern bool ah_rw_juken(ah_rw_t* rw, size_t size)
{
    ah_assert(rw != NULL);

    if (ah_unlikely((size_t) (rw->e - rw->w) < size)) {
        return false;
    }

    rw->w = &rw->w[size];

    return true;
}
