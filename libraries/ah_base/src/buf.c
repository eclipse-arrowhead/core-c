// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include <string.h>

ah_extern void ah_buf_rw_init_for_writing(ah_buf_rw_t* rw, ah_buf_t* buf)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(buf != NULL);

    uint8_t* base = ah_buf_get_base(buf);
    uint8_t* end = &base[ah_buf_get_size(buf)]; // This is safe as long as `buf` is valid.

    *rw = (ah_buf_rw_t) {
        .rd = base,
        .wr = base,
        .end = end,
    };
}

ah_extern void ah_buf_rw_init_for_reading(ah_buf_rw_t* rw, const ah_buf_t* buf)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(buf != NULL);

    const uint8_t* base = ah_buf_get_base_const(buf);
    const uint8_t* end = &base[ah_buf_get_size(buf)]; // This is safe as long as `buf` is valid.

    *rw = (ah_buf_rw_t) {
        .rd = base,
        .wr = (uint8_t*) end,
        .end = end,
    };
}

ah_extern bool ah_buf_rw_copy1(ah_buf_rw_t* src, ah_buf_rw_t* dst)
{
    ah_assert_if_debug(src != NULL);
    ah_assert_if_debug(dst != NULL);

    if (ah_unlikely(src->wr == src->rd)) {
        return false;
    }

    if (ah_unlikely(dst->end == dst->wr)) {
        return false;
    }

    *dst->wr = *src->rd;
    src->rd = &src->rd[1u];
    dst->wr = &dst->wr[1u];

    return true;
}

ah_extern bool ah_buf_rw_copyn(ah_buf_rw_t* src, ah_buf_rw_t* dst, size_t size)
{
    ah_assert_if_debug(src != NULL);
    ah_assert_if_debug(dst != NULL);

    if (ah_unlikely((size_t) (src->wr - src->rd) < size)) {
        return false;
    }

    if (ah_unlikely((size_t) (dst->end - dst->wr) < size)) {
        return false;
    }

    memcpy(dst->wr, src->rd, size);
    src->rd = &src->rd[size];
    dst->wr = &dst->wr[size];

    return true;
}

ah_extern bool ah_buf_rw_peek1(ah_buf_rw_t* rw, uint8_t* dst)
{
    ah_assert_if_debug(rw != NULL);

    if (ah_unlikely(rw->rd == rw->wr)) {
        return false;
    }

    *dst = *rw->rd;

    return true;
}

ah_extern bool ah_buf_rw_peekn(ah_buf_rw_t* rw, uint8_t* dst, size_t size)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(dst != NULL);

    if (ah_unlikely((size_t) (rw->wr - rw->rd) < size)) {
        return false;
    }

    memcpy(dst, rw->rd, size);

    return true;
}

ah_extern bool ah_buf_rw_read1(ah_buf_rw_t* rw, uint8_t* dst)
{
    ah_assert_if_debug(rw != NULL);

    if (ah_unlikely(rw->rd == rw->wr)) {
        return false;
    }

    *dst = *rw->rd;
    rw->rd = &rw->rd[1u];

    return true;
}

ah_extern bool ah_buf_rw_readn(ah_buf_rw_t* rw, uint8_t* dst, size_t size)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(dst != NULL);

    if (ah_unlikely((size_t) (rw->wr - rw->rd) < size)) {
        return false;
    }

    memcpy(dst, rw->rd, size);
    rw->rd = &rw->rd[size];

    return true;
}

ah_extern bool ah_buf_rw_skip1(ah_buf_rw_t* rw)
{
    ah_assert_if_debug(rw != NULL);

    if (ah_unlikely(rw->wr == rw->rd)) {
        return false;
    }

    rw->rd = &rw->rd[1u];

    return true;
}

ah_extern bool ah_buf_rw_skipn(ah_buf_rw_t* rw, size_t size)
{
    ah_assert_if_debug(rw != NULL);

    if (ah_unlikely((size_t) (rw->wr - rw->rd) < size)) {
        return false;
    }

    rw->rd = &rw->rd[size];

    return true;
}

ah_extern bool ah_buf_rw_write1(ah_buf_rw_t* rw, uint8_t byte)
{
    ah_assert_if_debug(rw != NULL);

    if (ah_unlikely(rw->wr == rw->end)) {
        return false;
    }

    *rw->wr = byte;
    rw->wr = &rw->wr[1u];

    return true;
}

ah_extern bool ah_buf_rw_writen(ah_buf_rw_t* rw, uint8_t* src, size_t size)
{
    ah_assert_if_debug(src != NULL);
    ah_assert_if_debug(rw != NULL);

    if (ah_unlikely((size_t) (rw->end - rw->wr) < size)) {
        return false;
    }

    memcpy(rw->wr, src, size);
    rw->wr = &rw->wr[size];

    return true;
}
