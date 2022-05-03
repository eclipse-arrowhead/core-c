// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/err.h"

ah_extern ah_err_t ah_tcp_omsg_init(ah_tcp_omsg_t* omsg, ah_bufs_t bufs)
{
    if (omsg == NULL || (bufs.items == NULL && bufs.length != 0u)) {
        return AH_EINVAL;
    }

    struct iovec* iov;
    int iovcnt;

    ah_err_t err = ah_i_bufs_into_iovec(&bufs, &iov, &iovcnt);
    if (err != AH_ENONE) {
        return err;
    }

    *omsg = (ah_tcp_omsg_t) {
        ._next = NULL,
        ._iov = iov,
        ._iovcnt = iovcnt,
    };

    return AH_ENONE;
}

ah_extern ah_bufs_t ah_tcp_omsg_get_bufs(ah_tcp_omsg_t* omsg)
{
    ah_assert_if_debug(omsg != NULL);

    ah_bufs_t bufs;
    ah_i_bufs_from_iovec(&bufs, omsg->_iov, omsg->_iovcnt);

    return bufs;
}
