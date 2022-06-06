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
    uint8_t* rd;
    uint8_t* wr;
    uint8_t* end;
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

ah_extern void ah_buf_rw_init_for_writing_to(ah_buf_rw_t* rw, ah_buf_t* buf);
ah_extern void ah_buf_rw_init_for_reading_from(ah_buf_rw_t* rw, const ah_buf_t* buf);
ah_extern void ah_buf_rw_get_readable_as_buf(const ah_buf_rw_t* rw, ah_buf_t* buf);
ah_extern size_t ah_buf_rw_get_readable_size(const ah_buf_rw_t* rw);
ah_extern void ah_buf_rw_get_writable_as_buf(const ah_buf_rw_t* rw, ah_buf_t* buf);
ah_extern size_t ah_buf_rw_get_writable_size(const ah_buf_rw_t* rw);
ah_extern bool ah_buf_rw_is_containing_buf(const ah_buf_rw_t* rw, const ah_buf_t* buf);
ah_extern bool ah_buf_rw_copy1(ah_buf_rw_t* src, ah_buf_rw_t* dst);
ah_extern bool ah_buf_rw_copyn(ah_buf_rw_t* src, ah_buf_rw_t* dst, size_t size);
ah_extern bool ah_buf_rw_peek1(ah_buf_rw_t* rw, uint8_t* dst);
ah_extern bool ah_buf_rw_peekn(ah_buf_rw_t* rw, uint8_t* dst, size_t size);
ah_extern bool ah_buf_rw_read1(ah_buf_rw_t* rw, uint8_t* dst);
ah_extern bool ah_buf_rw_readn(ah_buf_rw_t* rw, uint8_t* dst, size_t size);
ah_extern bool ah_buf_rw_skip1(ah_buf_rw_t* rw);
ah_extern bool ah_buf_rw_skipn(ah_buf_rw_t* rw, size_t size);
ah_extern bool ah_buf_rw_writen(ah_buf_rw_t* rw, uint8_t* src, size_t size);
ah_extern bool ah_buf_rw_write1(ah_buf_rw_t* rw, uint8_t byte);
ah_extern bool ah_buf_rw_juke1(ah_buf_rw_t* rw);
ah_extern bool ah_buf_rw_juken(ah_buf_rw_t* rw, size_t size);

#endif
