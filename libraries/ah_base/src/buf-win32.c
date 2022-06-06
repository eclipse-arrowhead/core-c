// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include "ah/assert.h"
#include "ah/err.h"

#include <winsock2.h>

#include <limits.h>

ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, uint8_t* base, size_t size)
{
    if (buf == NULL || (base == NULL && size != 0)) {
        return AH_EINVAL;
    }

    if (((uintmax_t) size) > ((uintmax_t) ULONG_MAX)) {
        return AH_EDOM;
    }

    buf->_size = (ULONG) size;
    buf->_base = base;

    return AH_ENONE;
}

ah_extern ah_buf_t ah_buf_from(uint8_t* base, uint32_t size)
{
    ah_assert(base != NULL || size == 0u);

    return (ah_buf_t) { size, base };
}

ah_extern void ah_buf_limit_size_to(ah_buf_t* buf, size_t limit)
{
    ah_assert(buf != NULL);

    if (buf->_size > limit) {
        buf->_size = (ULONG) limit;
    }
}

ah_extern void ah_buf_skipn(ah_buf_t* buf, size_t size)
{
    ah_assert(buf != NULL);

    if (size > ULONG_MAX) {
        size = ULONG_MAX;
    }
    if (size > buf->_size) {
        size = buf->_size;
    }

    buf->_base = &buf->_base[size];
    buf->_size = buf->_size - size;
}
