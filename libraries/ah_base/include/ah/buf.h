// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_BUF_H_
#define AH_BUF_H_

#include "assert.h"
#include "internal/_buf.h"
#include "math.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ah_buf {
    // Will always have two fields: `_base` and `_size`. Their order and types
    // will vary, however, with the targeted platform. Use ah_buf_init() to
    // update and ah_buf_get_base() and ah_buf_get_size() to query.

    AH_I_BUF_FIELDS
};

// Points into a block of memory as follows:
//
//                         rd           wr                     end
//                          |           |                       |
//                          V           V                       V
//              +---+---+---+---+---+---+---+---+---+---+---+---+
// Memory block | 1 | 7 | 3 | 2 | 4 | 1 | X | X | X | X | X | X |
//              +---+---+---+---+---+---+---+---+---+---+---+---+
//                           :.........: :.....................:
//                                :                 :
//                         Readable bytes     Writable bytes
struct ah_buf_rw {
    const uint8_t* rd;
    uint8_t* wr;
    const uint8_t* end;
};

struct ah_bufs {
    ah_buf_t* items;
    size_t length;
};

// Error codes:
// * AH_EINVAL       - `buf` is NULL or `base` is NULL and `size` is positive.
// * AH_EDOM [Win32] - `size` is too large to be representable by `buf`.
ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, uint8_t* base, size_t size);

// Note that `size` is 32-bit, in contrast to the `size` of `ah_buf_init`.
ah_extern ah_buf_t ah_buf_from(uint8_t* base, uint32_t size);

ah_inline uint8_t* ah_buf_get_base(ah_buf_t* buf)
{
    ah_assert_if_debug(buf != NULL);
    return (uint8_t*) buf->_base;
}

ah_inline const uint8_t* ah_buf_get_base_const(const ah_buf_t* buf)
{
    ah_assert_if_debug(buf != NULL);
    return (const uint8_t*) buf->_base;
}

ah_inline size_t ah_buf_get_size(const ah_buf_t* buf)
{
    ah_assert_if_debug(buf != NULL);
    return (size_t) buf->_size;
}

ah_inline bool ah_buf_is_empty(const ah_buf_t* buf)
{
    ah_assert_if_debug(buf != NULL);
    return buf->_base == NULL || buf->_size == 0u;
}

ah_extern void ah_buf_rw_init_for_writing(ah_buf_rw_t* rw, ah_buf_t* buf);
ah_extern void ah_buf_rw_init_for_reading(ah_buf_rw_t* rw, const ah_buf_t* buf);

ah_inline void ah_buf_rw_get_readable_as_buf(const ah_buf_rw_t* rw, ah_buf_t* buf)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(buf != NULL);

    *buf = (ah_buf_t) {
        ._base = (uint8_t*) rw->rd,
        ._size = (size_t) (rw->wr - rw->rd),
    };
}

ah_inline size_t ah_buf_rw_get_readable_size(const ah_buf_rw_t* rw)
{
    ah_assert_if_debug(rw != NULL);
    return (size_t) (rw->wr - rw->rd);
}

ah_inline void ah_buf_rw_get_writable_as_buf(const ah_buf_rw_t* rw, ah_buf_t* buf)
{
    ah_assert_if_debug(rw != NULL);
    ah_assert_if_debug(buf != NULL);

    *buf = (ah_buf_t) {
        ._base = (uint8_t*) rw->wr,
        ._size = (size_t) (rw->end - rw->wr),
    };
}

ah_inline size_t ah_buf_rw_get_writable_size(const ah_buf_rw_t* rw)
{
    ah_assert_if_debug(rw != NULL);
    return (size_t) (rw->end - rw->wr);
}

ah_extern bool ah_buf_rw_copy1(ah_buf_rw_t* src, ah_buf_rw_t* dst);
ah_extern bool ah_buf_rw_copyn(ah_buf_rw_t* src, ah_buf_rw_t* dst, size_t size);
ah_extern bool ah_buf_rw_peek1(ah_buf_rw_t* rw, uint8_t* dst);
ah_extern bool ah_buf_rw_peekn(ah_buf_rw_t* rw, uint8_t* dst, size_t size);
ah_extern bool ah_buf_rw_read1(ah_buf_rw_t* rw, uint8_t* dst);
ah_extern bool ah_buf_rw_readn(ah_buf_rw_t* rw, uint8_t* dst, size_t size);
ah_extern bool ah_buf_rw_skip1(ah_buf_rw_t* rw);
ah_extern bool ah_buf_rw_skipn(ah_buf_rw_t* rw, size_t size);
ah_extern bool ah_buf_rw_write1(ah_buf_rw_t* rw, uint8_t byte);
ah_extern bool ah_buf_rw_writen(ah_buf_rw_t* rw, uint8_t* src, size_t size);

#endif
