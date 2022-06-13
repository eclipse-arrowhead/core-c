// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_RW_H_
#define AH_RW_H_

#include "defs.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Points into a block of memory as follows:
//
//                          r           w                       e
//                          |           |                       |
//                          V           V                       V
//              +---+---+---+---+---+---+---+---+---+---+---+---+
// Memory block | 1 | 7 | 3 | 2 | 4 | 1 | X | X | X | X | X | X |
//              +---+---+---+---+---+---+---+---+---+---+---+---+
//                           :.........: :.....................:
//                                :                 :
//                         Readable bytes     Writable bytes
struct ah_rw {
    uint8_t* r; // Read index.
    uint8_t* w; // Write index.
    uint8_t* e; // End.
};

ah_extern void ah_rw_init_for_writing_to(ah_rw_t* rw, ah_buf_t* buf);
ah_extern void ah_rw_init_for_reading_from(ah_rw_t* rw, const ah_buf_t* buf);
ah_extern void ah_rw_get_readable_as_buf(const ah_rw_t* rw, ah_buf_t* buf);
ah_extern size_t ah_rw_get_readable_size(const ah_rw_t* rw);
ah_extern void ah_rw_get_writable_as_buf(const ah_rw_t* rw, ah_buf_t* buf);
ah_extern size_t ah_rw_get_writable_size(const ah_rw_t* rw);
ah_extern bool ah_rw_is_containing_buf(const ah_rw_t* rw, const ah_buf_t* buf);
ah_extern bool ah_rw_copy1(ah_rw_t* src, ah_rw_t* dst);
ah_extern bool ah_rw_copyn(ah_rw_t* src, ah_rw_t* dst, size_t size);
ah_extern bool ah_rw_peek1(ah_rw_t* rw, uint8_t* dst);
ah_extern bool ah_rw_peekn(ah_rw_t* rw, uint8_t* dst, size_t size);
ah_extern bool ah_rw_read1(ah_rw_t* rw, uint8_t* dst);
ah_extern bool ah_rw_readn(ah_rw_t* rw, uint8_t* dst, size_t size);
ah_extern bool ah_rw_skip1(ah_rw_t* rw);
ah_extern bool ah_rw_skipn(ah_rw_t* rw, size_t size);
ah_extern bool ah_rw_writen(ah_rw_t* rw, uint8_t* src, size_t size);
ah_extern bool ah_rw_write1(ah_rw_t* rw, uint8_t byte);
ah_extern bool ah_rw_juke1(ah_rw_t* rw);
ah_extern bool ah_rw_juken(ah_rw_t* rw, size_t size);

#endif
