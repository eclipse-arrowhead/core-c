// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/err.h"

ah_extern ah_err_t ah_udp_omsg_init(ah_udp_omsg_t* omsg, ah_bufs_t bufs, ah_sockaddr_t* raddr)
{
    if (omsg == NULL || (bufs.items == NULL && bufs.length != 0u) || raddr == NULL) {
        return AH_EINVAL;
    }

    struct iovec* iov;
    int iovlen;

    ah_err_t err = ah_i_bufs_into_iovec(&bufs, &iov, &iovlen);
    if (err != AH_ENONE) {
        return err;
    }

    *omsg = (ah_udp_omsg_t) {
        ._next = NULL,
        ._msghdr.msg_name = ah_i_sockaddr_into_bsd(raddr),
        ._msghdr.msg_namelen = ah_i_sockaddr_get_size(raddr),
        ._msghdr.msg_iov = iov,
        ._msghdr.msg_iovlen = iovlen,
    };

    return AH_ENONE;
}

ah_extern ah_sockaddr_t* ah_udp_omsg_get_raddr(ah_udp_omsg_t* omsg)
{
    ah_assert_if_debug(omsg != NULL);
    return ah_i_sockaddr_from_bsd(omsg->_msghdr.msg_name);
}

ah_extern ah_bufs_t ah_udp_omsg_get_bufs(ah_udp_omsg_t* omsg)
{
    ah_assert_if_debug(omsg != NULL);

    ah_bufs_t bufs;
    ah_i_bufs_from_iovec(&bufs, omsg->_msghdr.msg_iov, omsg->_msghdr.msg_iovlen);

    return bufs;
}
