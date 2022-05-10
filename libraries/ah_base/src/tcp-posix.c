// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/err.h"

ah_extern ah_err_t ah_tcp_obufs_init(ah_tcp_obufs_t* obufs, ah_bufs_t bufs)
{
    if (obufs == NULL || (bufs.items == NULL && bufs.length != 0u)) {
        return AH_EINVAL;
    }

    struct iovec* iov;
    int iovcnt;

    ah_err_t err = ah_i_bufs_into_iovecs(&bufs, &iov, &iovcnt);
    if (err != AH_ENONE) {
        return err;
    }

    *obufs = (ah_tcp_obufs_t) {
        ._next = NULL,
        ._iov = iov,
        ._iovcnt = iovcnt,
    };

    return AH_ENONE;
}

ah_extern ah_bufs_t ah_tcp_obufs_unwrap(ah_tcp_obufs_t* obufs)
{
    ah_assert_if_debug(obufs != NULL);

    ah_bufs_t bufs;
    ah_i_bufs_from_iovec(&bufs, obufs->_iov, obufs->_iovcnt);

    return bufs;
}
