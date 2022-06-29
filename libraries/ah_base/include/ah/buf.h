// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_BUF_H_
#define AH_BUF_H_

#include "internal/_buf.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define AH_BUF_SIZE_MAX AH_I_BUF_SIZE_MAX

struct ah_buf {
    // Will always have two fields: `_base` and `_size`. Their order and types
    // will vary, however, with the targeted platform. Use ah_buf_init() to
    // update and ah_buf_get_base() and ah_buf_get_size() to query.

    AH_I_BUF_FIELDS
};

// Error codes:
// * AH_EINVAL       - `buf` is NULL or `base` is NULL and `size` is positive.
// * AH_EDOM [Win32] - `size` is larger than AH_BUF_SIZE_MAX.
ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, uint8_t* base, size_t size);

// Note that `size` is always 32-bits, in contrast to the `size` parameter of
// `ah_buf_init`.
ah_extern ah_buf_t ah_buf_from(uint8_t* base, uint32_t size);

ah_extern uint8_t* ah_buf_get_base(ah_buf_t* buf);
ah_extern const uint8_t* ah_buf_get_base_const(const ah_buf_t* buf);
ah_extern size_t ah_buf_get_size(const ah_buf_t* buf);
ah_extern bool ah_buf_is_empty(const ah_buf_t* buf);
ah_extern void ah_buf_limit_size_to(ah_buf_t* buf, size_t limit);
ah_extern void ah_buf_skipn(ah_buf_t* buf, size_t size);

#endif
