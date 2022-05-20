// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"

ah_extern ah_err_t ah_tcp_msg_init(ah_tcp_msg_t* msg, ah_bufs_t bufs)
{
    if (msg == NULL || (bufs.items == NULL && bufs.length != 0u)) {
        return AH_EINVAL;
    }

    struct iovec* iov;
    int iovcnt;

    ah_err_t err = ah_i_bufs_into_iovecs(&bufs, &iov, &iovcnt);
    if (err != AH_ENONE) {
        return err;
    }

    *msg = (ah_tcp_msg_t) {
        ._next = NULL,
        ._iov = iov,
        ._iovcnt = iovcnt,
    };

    return AH_ENONE;
}

ah_extern ah_bufs_t ah_tcp_msg_unwrap(ah_tcp_msg_t* msg)
{
    ah_assert_if_debug(msg != NULL);

    ah_bufs_t bufs;
    ah_i_bufs_from_iovec(&bufs, msg->_iov, msg->_iovcnt);

    return bufs;
}
