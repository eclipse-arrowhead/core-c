// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#if AH_USE_IOVEC
#    include "ah/assert.h"

#    include <limits.h>
#    include <sys/uio.h>

ah_extern ah_err_t ah_bufvec_from_iovec(struct ah_bufvec* bufvec, struct iovec* iov, int iovcnt)
{
    ah_assert_if_debug(bufvec != NULL);
    ah_assert_if_debug(iov != NULL);

    if (iovcnt < 0 || ((uintmax_t) iovcnt) > ((uintmax_t) SIZE_MAX)) {
        return AH_EOVERFLOW;
    }

    bufvec->items = (struct ah_buf*) iov;
    bufvec->length = iovcnt;

    return AH_ENONE;
}

ah_extern ah_err_t ah_bufvec_into_iovec(struct ah_bufvec* bufvec, struct iovec** iov, int* iovcnt)
{
    ah_assert_if_debug(bufvec != NULL);
    ah_assert_if_debug(iov != NULL);
    ah_assert_if_debug(iovcnt != NULL);

    if (bufvec->length > INT_MAX) {
        return AH_EOVERFLOW;
    }

    *iov = (struct iovec*) bufvec->items;
    *iovcnt = (int) bufvec->length;

    return AH_ENONE;
}

#endif
