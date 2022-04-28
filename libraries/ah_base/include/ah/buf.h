// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_BUF_H_
#define AH_BUF_H_

#include "assert.h"
#include "internal/buf.h"

#include <stddef.h>
#include <stdint.h>

struct ah_buf {

    // Will always have two fields: `_octets` and `_size`. Their order and types
    // will vary, however, with the targeted platform. Use ah_buf_set() to
    // update and ah_buf_get_octets() and ah_buf_get_size() to query.

    AH_I_BUF_FIELDS
};

struct ah_bufvec {
    ah_buf_t* items;
    size_t length;
};

ah_inline uint8_t* ah_buf_get_octets(const ah_buf_t* buf)
{
    ah_assert_if_debug(buf != NULL);

    return (uint8_t*) buf->_octets;
}

ah_inline size_t ah_buf_get_size(const ah_buf_t* buf)
{
    ah_assert_if_debug(buf != NULL);

    return (size_t) buf->_size;
}

// Error codes:
// * AH_EINVAL       - `buf` is NULL or `octets` is NULL and `size` is positive.
// * AH_EDOM [Win32] - `size` is too large to be representable by `buf`.
ah_extern ah_err_t ah_buf_set(ah_buf_t* buf, uint8_t* octets, size_t size);

#endif
