// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include "ah/assert.h"
#include "ah/err.h"

#include <limits.h>
#include <sys/uio.h>

ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, uint8_t* octets, size_t size)
{
    if (buf == NULL || (octets == NULL && size != 0)) {
        return AH_EINVAL;
    }

    buf->_octets = octets;
    buf->_size = size;

    return AH_ENONE;
}

ah_extern void ah_i_bufs_from_iovec(ah_bufs_t* bufs, struct iovec* iov, size_t iovcnt)
{
    ah_assert_if_debug(bufs != NULL && iov != NULL);

    bufs->items = (ah_buf_t*) iov;
    bufs->length = iovcnt;
}

ah_extern ah_err_t ah_i_bufs_into_iovec(ah_bufs_t* bufs, struct iovec** iov, int* iovcnt)
{
    ah_assert_if_debug(bufs != NULL && iov != NULL && iovcnt != NULL);

    if (bufs->length > INT_MAX) {
        return AH_EOVERFLOW;
    }

    *iov = (struct iovec*) bufs->items;
    *iovcnt = (int) bufs->length;

    return AH_ENONE;
}
