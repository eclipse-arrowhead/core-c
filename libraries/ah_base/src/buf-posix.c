// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include "ah/assert.h"
#include "ah/err.h"

#include <limits.h>
#include <sys/uio.h>

ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, uint8_t* base, size_t size)
{
    if (buf == NULL || (base == NULL && size != 0)) {
        return AH_EINVAL;
    }

    buf->base = base;
    buf->size = size;

    return AH_ENONE;
}

ah_extern ah_buf_t ah_buf_from(uint8_t* base, uint32_t size)
{
    ah_assert(base != NULL || size == 0u);

    return (ah_buf_t) { base, size };
}
