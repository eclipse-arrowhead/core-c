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
        return AH_EOVERFLOW;
    }

    buf->size = (ULONG) size;
    buf->base = base;

    return AH_ENONE;
}

ah_extern ah_buf_t ah_buf_from(uint8_t* base, uint32_t size)
{
    ah_assert_always(base != NULL || size == 0u);

    return (ah_buf_t) { size, base };
}
