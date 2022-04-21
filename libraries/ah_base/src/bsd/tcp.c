// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/tcp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#include <stddef.h>

#if AH_HAS_POSIX
#    include <netinet/tcp.h>
#    include <sys/socket.h>
#elif AH_IS_WIN32
#    include <winsock2.h>
#endif

#if AH_IS_WIN32
#    define SHUT_RD   SD_RECEIVE
#    define SHUT_WR   SD_SEND
#    define SHUT_RDWR SD_BOTH
#endif

ah_extern ah_err_t ah_tcp_open(ah_tcp_sock_t* sock, ah_loop_t* loop, const ah_sockaddr_t* local_addr, ah_tcp_open_cb cb)
{
    if (sock == NULL || loop == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }

    ah_i_sockfd_t fd;
    ah_err_t err = ah_i_sock_open_bind(loop, AH_I_SOCK_STREAM, local_addr, &fd);

    if (err == AH_ENONE) {
        *sock = (ah_tcp_sock_t) {
            ._loop = loop,
            ._fd = fd,
            ._state = AH_I_TCP_STATE_OPEN,
        };
#if AH_USE_IOCP
        sock->_sockfamily = local_addr->as_ip.family;
#endif
    }

    if (cb != NULL) {
        cb(sock, err);
        return AH_ENONE;
    }

    return err;
}

ah_extern ah_err_t ah_tcp_get_local_addr(const ah_tcp_sock_t* sock, ah_sockaddr_t* local_addr)
{
    if (sock == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (AH_I_TCP_STATE_OPEN | AH_I_TCP_STATE_CONNECTED | AH_I_TCP_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }
    return ah_i_sock_getsockname(sock->_fd, local_addr);
}

ah_extern ah_err_t ah_tcp_get_remote_addr(const ah_tcp_sock_t* sock, ah_sockaddr_t* remote_addr)
{
    if (sock == NULL || remote_addr == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (AH_I_TCP_STATE_OPEN | AH_I_TCP_STATE_CONNECTED | AH_I_TCP_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }
    return ah_i_sock_getpeername(sock->_fd, remote_addr);
}

ah_extern ah_err_t ah_tcp_set_keepalive(ah_tcp_sock_t* sock, bool keepalive)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (AH_I_TCP_STATE_OPEN | AH_I_TCP_STATE_CONNECTED | AH_I_TCP_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }
    int value = keepalive ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_KEEPALIVE, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_set_no_delay(ah_tcp_sock_t* sock, bool no_delay)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (AH_I_TCP_STATE_OPEN | AH_I_TCP_STATE_CONNECTED | AH_I_TCP_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }
    int value = no_delay ? 1 : 0;
    if (setsockopt(sock->_fd, IPPROTO_TCP, TCP_NODELAY, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_set_reuse_addr(ah_tcp_sock_t* sock, bool reuse_addr)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if ((sock->_state & (AH_I_TCP_STATE_OPEN | AH_I_TCP_STATE_CONNECTED | AH_I_TCP_STATE_LISTENING)) == 0u) {
        return AH_ESTATE;
    }
    int value = reuse_addr ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_extern ah_err_t ah_tcp_shutdown(ah_tcp_sock_t* sock, ah_tcp_shutdown_t flags)
{
    if (sock == NULL || (flags & ~AH_TCP_SHUTDOWN_RDWR) != 0u) {
        return AH_EINVAL;
    }
    if ((flags & AH_TCP_SHUTDOWN_RDWR) == 0u) {
        return AH_ENONE;
    }
    if (sock->_state != AH_I_TCP_STATE_CONNECTED) {
        return AH_ESTATE;
    }

#if SHUT_RD == (AH_TCP_SHUTDOWN_RD - 1) && SHUT_WR == (AH_TCP_SHUTDOWN_WR - 1)                                         \
    && SHUT_RDWR == (AH_TCP_SHUTDOWN_RDWR - 1)

    const int how = ((int) flags) - 1;

#else

    int how;
    switch (flags) {
    case AH_TCP_SHUTDOWN_RD:
        how = SHUT_RD;
        break;

    case AH_TCP_SHUTDOWN_WR:
        how = SHUT_WR;
        break;

    case AH_TCP_SHUTDOWN_RDWR:
        how = SHUT_RDWR;
        break;

    default:
        ah_unreachable();
    }

#endif

    ah_err_t err;

    if (shutdown(sock->_fd, how) != 0) {
#if AH_IS_WIN32
        err = WSAGetLastError();
#else
        err = errno;
#endif
    }
    else {
        err = AH_ENONE;

        if ((flags & AH_TCP_SHUTDOWN_RD) != 0) {
            sock->_state_read = AH_I_TCP_STATE_READ_OFF;
        }
        if ((flags & AH_TCP_SHUTDOWN_WR) != 0) {
            sock->_state_write = AH_I_TCP_STATE_WRITE_OFF;
        }
    }

    return err;
}
