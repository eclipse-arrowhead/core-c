// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include "ah/assert.h"

#include <string.h>

ah_extern uint8_t* ah_buf_get_base(ah_buf_t* buf)
{
    ah_assert(buf != NULL);

    return (uint8_t*) buf->_base;
}

ah_extern const uint8_t* ah_buf_get_base_const(const ah_buf_t* buf)
{
    ah_assert(buf != NULL);

    return (const uint8_t*) buf->_base;
}

ah_extern size_t ah_buf_get_size(const ah_buf_t* buf)
{
    ah_assert(buf != NULL);

    return (size_t) buf->_size;
}

ah_extern bool ah_buf_is_empty(const ah_buf_t* buf)
{
    ah_assert(buf != NULL);

    return buf->_base == NULL || buf->_size == 0u;
}
