// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include "ah/assert.h"

ah_extern bool ah_buf_is_empty(const ah_buf_t* buf)
{
    if (buf == NULL) {
        return true;
    }
    return buf->base == NULL || buf->size == 0u;
}
