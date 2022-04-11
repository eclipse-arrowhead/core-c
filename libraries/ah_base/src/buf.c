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
#endif

#if AH_USE_IOVEC
ah_extern ah_err_t ah_bufvec_to_iovec(struct ah_bufvec* bufvec, struct iovec** iov, int* iovcnt)
{
    ah_assert_if_debug(offsetof(struct iovec, iov_base) == offsetof(struct ah_buf, octets));
    ah_assert_if_debug(offsetof(struct iovec, iov_len) == offsetof(struct ah_buf, size));
    ah_assert_if_debug(sizeof(struct iovec) == sizeof(struct ah_buf));

    if (bufvec == NULL || iov == NULL || iovcnt == NULL) {
        return AH_EINVAL;
    }

    if (bufvec->length > INT_MAX) {
        *iovcnt = -1;
        return AH_EOVERFLOW;
    }

    *iov = (struct iovec*) bufvec->items;
    *iovcnt = (int) bufvec->length;

    return AH_ENONE;
}
#endif
