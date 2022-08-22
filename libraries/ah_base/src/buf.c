// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include "ah/assert.h"


ah_extern bool ah_buf_is_empty(const ah_buf_t* buf)
{
    ah_assert(buf != NULL);

    return buf->base == NULL || buf->size == 0u;
}
