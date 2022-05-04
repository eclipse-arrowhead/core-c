// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_BUF_H_
#define AH_BUF_H_

#include "assert.h"
#include "internal/_buf.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct ah_buf {

    // Will always have two fields: `_base` and `_size`. Their order and types
    // will vary, however, with the targeted platform. Use ah_buf_init() to
    // update and ah_buf_get_base() and ah_buf_get_size() to query.

    AH_I_BUF_FIELDS
};

struct ah_bufs {
    ah_buf_t* items;
    size_t length;
};

// Error codes:
// * AH_EINVAL       - `buf` is NULL or `base` is NULL and `size` is positive.
// * AH_EDOM [Win32] - `size` is too large to be representable by `buf`.
ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, uint8_t* base, size_t size);

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

ah_extern ah_err_t ah_buf_shrinkl(ah_buf_t* buf, size_t size);

#endif
