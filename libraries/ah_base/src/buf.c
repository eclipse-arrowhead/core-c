// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/buf.h"

#include "ah/assert.h"
#include "ah/err.h"

#include <limits.h>

#if AH_IS_WIN32
#    include <winsock2.h>
#elif AH_USE_POSIX
#    include <sys/uio.h>
#endif

#if AH_IS_WIN32

ah_extern ah_err_t ah_bufvec_from_wsabufs(ah_bufvec_t* bufvec, WSABUF* buffers, ULONG buffer_count)
{
    ah_assert_if_debug(bufvec != NULL);
    ah_assert_if_debug(buffers != NULL);

    if (((uintmax_t) buffer_count) > ((uintmax_t) SIZE_MAX)) {
        return AH_EOVERFLOW;
    }

    bufvec->items = (ah_buf_t*) buffers;
    bufvec->length = buffer_count;

    return AH_ENONE;
}

ah_extern ah_err_t ah_bufvec_into_wsabufs(ah_bufvec_t* bufvec, WSABUF** buffers, ULONG* buffer_count)
{
    ah_assert_if_debug(bufvec != NULL);
    ah_assert_if_debug(buffers != NULL);
    ah_assert_if_debug(buffer_count != NULL);

    if (bufvec->length > ULONG_MAX) {
        return AH_EOVERFLOW;
    }

    *buffers = (WSABUF*) bufvec->items;
    *buffer_count = (ULONG) bufvec->length;

    return AH_ENONE;
}

#elif AH_USE_POSIX

ah_extern ah_err_t ah_bufvec_from_iovec(ah_bufvec_t* bufvec, struct iovec* iov, int iovcnt)
{
    ah_assert_if_debug(bufvec != NULL);
    ah_assert_if_debug(iov != NULL);

    if (iovcnt < 0 || ((uintmax_t) iovcnt) > ((uintmax_t) SIZE_MAX)) {
        return AH_EOVERFLOW;
    }

    bufvec->items = (ah_buf_t*) iov;
    bufvec->length = iovcnt;

    return AH_ENONE;
}

ah_extern ah_err_t ah_bufvec_into_iovec(ah_bufvec_t* bufvec, struct iovec** iov, int* iovcnt)
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
