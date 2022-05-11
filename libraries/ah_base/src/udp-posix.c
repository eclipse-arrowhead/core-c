// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"

ah_extern ah_err_t ah_udp_obufs_init(ah_udp_obufs_t* obufs, ah_bufs_t bufs, ah_sockaddr_t* raddr)
{
    if (obufs == NULL || (bufs.items == NULL && bufs.length != 0u) || raddr == NULL) {
        return AH_EINVAL;
    }

    struct iovec* iov;
    int iovlen;

    ah_err_t err = ah_i_bufs_into_iovecs(&bufs, &iov, &iovlen);
    if (err != AH_ENONE) {
        return err;
    }

    *obufs = (ah_udp_obufs_t) {
        ._next = NULL,
        ._msghdr.msg_name = ah_i_sockaddr_into_bsd(raddr),
        ._msghdr.msg_namelen = ah_i_sockaddr_get_size(raddr),
        ._msghdr.msg_iov = iov,
        ._msghdr.msg_iovlen = iovlen,
    };

    return AH_ENONE;
}

ah_extern ah_sockaddr_t* ah_udp_obufs_get_raddr(ah_udp_obufs_t* obufs)
{
    ah_assert_if_debug(obufs != NULL);
    return ah_i_sockaddr_from_bsd(obufs->_msghdr.msg_name);
}

ah_extern ah_bufs_t ah_udp_obufs_get_bufs(ah_udp_obufs_t* obufs)
{
    ah_assert_if_debug(obufs != NULL);

    ah_bufs_t bufs;
    ah_i_bufs_from_iovec(&bufs, obufs->_msghdr.msg_iov, obufs->_msghdr.msg_iovlen);

    return bufs;
}
