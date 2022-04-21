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

ah_extern ah_err_t ah_buf_set(ah_buf_t* buf, uint8_t* octets, size_t size)
{
    if (buf == NULL || (octets == NULL && size != 0)) {
        return AH_EINVAL;
    }

    buf->_octets = octets;
    buf->_size = size;

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_bufvec_from_iovec(ah_bufvec_t* bufvec, struct iovec* iov, int iovcnt)
{
    ah_assert_if_debug(bufvec != NULL && iov != NULL);

    if (iovcnt < 0 || ((uintmax_t) iovcnt) > ((uintmax_t) SIZE_MAX)) {
        return AH_EOVERFLOW;
    }

    bufvec->items = (ah_buf_t*) iov;
    bufvec->length = iovcnt;

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_bufvec_into_iovec(ah_bufvec_t* bufvec, struct iovec** iov, int* iovcnt)
{
    ah_assert_if_debug(bufvec != NULL && iov != NULL && iovcnt != NULL);

    if (bufvec->length > INT_MAX) {
        return AH_EOVERFLOW;
    }

    *iov = (struct iovec*) bufvec->items;
    *iovcnt = (int) bufvec->length;

    return AH_ENONE;
}
