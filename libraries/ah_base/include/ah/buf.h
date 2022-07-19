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
#if AH_IS_WIN32
    ULONG size; // Guaranteed to be of a size smaller than or equal to size_t.
    uint8_t* base;
#else
    uint8_t* base;
    size_t size;
#endif
};

// Error codes:
// * AH_EINVAL            - `buf` is NULL or `base` is NULL and `size` is positive.
// * AH_EOVERFLOW [Win32] - `size` is larger than AH_BUF_SIZE_MAX.
ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, uint8_t* base, size_t size);

// Note that `size` is always a 32-bit type, in contrast to the `size`
// parameter of `ah_buf_init`.
ah_extern ah_buf_t ah_buf_from(uint8_t* base, uint32_t size);

ah_extern bool ah_buf_is_empty(const ah_buf_t* buf);

#endif
