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
#elif AH_HAS_POSIX
#    include <sys/uio.h>
#endif

ah_extern ah_err_t ah_buf_init(ah_buf_t* buf, void* data, const size_t size)
{
    if (buf == NULL || (data == NULL && size != 0)) {
        return AH_EINVAL;
    }

    #if AH_IS_WIN32

    if (((uintmax_t) size) > ((uintmax_t) ULONG_MAX)) {
        return AH_EDOM;
    }

    buf->size = (ULONG) size;
    buf->octets = data;

    #elif AH_HAS_POSIX

    buf->octets = data;
    buf->size = size;

    #endif

    return AH_ENONE;
}

#if AH_IS_WIN32

ah_extern ah_err_t ah_bufvec_from_wsabufs(ah_bufvec_t* bufvec, WSABUF* buffers, ULONG buffer_count)
{
    if (bufvec == NULL || buffers == NULL) {
        return AH_EINVAL;
    }

    if (((uintmax_t) buffer_count) > ((uintmax_t) SIZE_MAX)) {
        return AH_EOVERFLOW;
    }

    bufvec->items = (ah_buf_t*) buffers;
    bufvec->length = buffer_count;

    return AH_ENONE;
}

ah_extern ah_err_t ah_bufvec_into_wsabufs(ah_bufvec_t* bufvec, WSABUF** buffers, ULONG* buffer_count)
{
    if (bufvec == NULL || buffers == NULL || buffer_count == NULL) {
        return AH_EINVAL;
    }

    if (bufvec->length > ULONG_MAX) {
        return AH_EOVERFLOW;
    }

    *buffers = (WSABUF*) bufvec->items;
    *buffer_count = (ULONG) bufvec->length;

    return AH_ENONE;
}

#elif AH_HAS_POSIX

ah_extern ah_err_t ah_bufvec_from_iovec(ah_bufvec_t* bufvec, struct iovec* iov, int iovcnt)
{
    if (bufvec == NULL || iov == NULL) {
        return AH_EINVAL;
    }

    if (iovcnt < 0 || ((uintmax_t) iovcnt) > ((uintmax_t) SIZE_MAX)) {
        return AH_EOVERFLOW;
    }

    bufvec->items = (ah_buf_t*) iov;
    bufvec->length = iovcnt;

    return AH_ENONE;
}

ah_extern ah_err_t ah_bufvec_into_iovec(ah_bufvec_t* bufvec, struct iovec** iov, int* iovcnt)
{
    if (bufvec == NULL || iov == NULL || iovcnt == NULL) {
        return AH_EINVAL;
    }

    if (bufvec->length > INT_MAX) {
        return AH_EOVERFLOW;
    }

    *iov = (struct iovec*) bufvec->items;
    *iovcnt = (int) bufvec->length;

    return AH_ENONE;
}

#endif
