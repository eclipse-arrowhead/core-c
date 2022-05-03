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

ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, uint8_t* octets, size_t size)
{
    if (buf == NULL || (octets == NULL && size != 0)) {
        return AH_EINVAL;
    }

    if (((uintmax_t) size) > ((uintmax_t) ULONG_MAX)) {
        return AH_EDOM;
    }

    buf->_size = (ULONG) size;
    buf->_octets = octets;

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_bufs_from_wsabufs(ah_bufs_t* bufs, WSABUF* buffers, ULONG buffer_count)
{
    ah_assert_if_debug(bufs != NULL && buffers != NULL);

    if (((uintmax_t) buffer_count) > ((uintmax_t) SIZE_MAX)) {
        return AH_EOVERFLOW;
    }

    bufs->items = (ah_buf_t*) buffers;
    bufs->length = buffer_count;

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_bufs_into_wsabufs(ah_bufs_t* bufs, WSABUF** buffers, ULONG* buffer_count)
{
    ah_assert_if_debug(bufs != NULL && buffers != NULL && buffer_count != NULL);

    if (bufs->length > MAXDWORD) {
        return AH_EOVERFLOW;
    }

    *buffers = (WSABUF*) bufs->items;
    *buffer_count = (ULONG) bufs->length;

    return AH_ENONE;
}
