// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/sock.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#if AH_IS_DARWIN
#    include <fcntl.h>
#elif AH_IS_WIN32
#    include <ws2ipdef.h>
#endif

#if AH_HAS_POSIX
#    include <unistd.h>
#endif

#if AH_IS_WIN32
#    define close closesocket
#endif

ah_extern ah_i_socklen_t ah_i_sockaddr_get_size(const ah_sockaddr_t* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);

#if AH_I_SOCKADDR_HAS_SIZE
    if (sockaddr->as_any.size != 0u) {
        return sockaddr->as_any.size;
    }
#endif

    switch (sockaddr->as_any.family) {
    case AH_I_SOCKFAMILY_IPV4:
        return sizeof(struct sockaddr_in);

    case AH_I_SOCKFAMILY_IPV6:
        return sizeof(struct sockaddr_in6);

    default:
        ah_abort();
    }
}

ah_extern ah_err_t ah_i_sock_open(ah_loop_t* loop, const int sockfamily, const int type, ah_i_sockfd_t* fd)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(fd != NULL);

    if (ah_loop_is_term(loop)) {
        return AH_ESTATE;
    }

    ah_i_sockfd_t fd0 = socket(sockfamily, type, 0);

#if AH_IS_WIN32

    if (fd0 == INVALID_SOCKET) {
        return WSAGetLastError();
    }

#else

    if (fd0 == -1) {
        return errno;
    }

#endif

    ah_err_t err;

#if AH_IS_DARWIN

    if (fcntl(fd0, F_SETFL, O_NONBLOCK, 0) == -1) {
        err = errno;
        goto close_fd0_and_return;
    }

#elif AH_USE_IOCP

    u_long value = 1;
    if (ioctlsocket(fd0, FIONBIO, &value) == SOCKET_ERROR) {
        err = WSAGetLastError();
        goto close_fd0_and_return;
    }

    if (!SetHandleInformation((HANDLE) fd0, HANDLE_FLAG_INHERIT, 0)) {
        err = GetLastError();
        goto close_fd0_and_return;
    }

    if (CreateIoCompletionPort((HANDLE) fd0, loop->_iocp_handle, 0u, 1u) == NULL) {
        err = GetLastError();
        goto close_fd0_and_return;
    }

#endif

    *fd = fd0;

    return AH_ENONE;

close_fd0_and_return:
    (void) close(fd0);

    return err;
}

ah_extern ah_err_t ah_i_sock_open_bind(struct ah_loop* loop, const int type, const ah_sockaddr_t* local_addr,
    ah_i_sockfd_t* fd)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(local_addr != NULL);
    ah_assert_if_debug(fd != NULL);

    ah_i_sockfd_t fd0;
    ah_err_t err = ah_i_sock_open(loop, local_addr->as_any.family, type, &fd0);
    if (err != AH_ENONE) {
        return err;
    }

    if (local_addr->as_ip.port != 0u || !ah_sockaddr_is_ip_wildcard(local_addr)) {
        if (bind(fd0, ah_i_sockaddr_const_into_bsd(local_addr), ah_i_sockaddr_get_size(local_addr)) != 0) {
#if AH_IS_WIN32
            err = WSAGetLastError();
#else
            err = errno;
#endif
            goto close_fd0_and_return;
        }
    }

    *fd = fd0;

    return AH_ENONE;

close_fd0_and_return:
    (void) close(fd0);

    return err;
}

ah_extern ah_err_t ah_i_sock_close(struct ah_loop* loop, ah_i_sockfd_t fd)
{
    ah_assert_if_debug(loop != NULL);

    if (close(fd) != 0) {
#if AH_IS_WIN32
        return WSAGetLastError();
#else
        if (!(errno == AH_EINTR && ah_i_loop_try_set_pending_err(loop, AH_EINTR))) {
            return errno;
        }
#endif
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_sock_getsockname(ah_i_sockfd_t fd, ah_sockaddr_t* local_addr)
{
    ah_assert_if_debug(local_addr != NULL);

    ah_i_socklen_t socklen = sizeof(ah_sockaddr_t);
    if (getsockname(fd, ah_i_sockaddr_into_bsd(local_addr), &socklen) != 0) {
        return errno;
    }

#if AH_I_SOCKADDR_HAS_SIZE
    ah_assert_if_debug(socklen <= UINT8_MAX);
    local_addr->as_any.size = (uint8_t) socklen;
#endif

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_sock_getpeername(ah_i_sockfd_t fd, ah_sockaddr_t* remote_addr)
{
    ah_assert_if_debug(remote_addr != NULL);

    ah_i_socklen_t socklen = sizeof(ah_sockaddr_t);
    if (getpeername(fd, ah_i_sockaddr_into_bsd(remote_addr), &socklen) != 0) {
        return errno;
    }

#if AH_I_SOCKADDR_HAS_SIZE
    ah_assert_if_debug(socklen <= UINT8_MAX);
    remote_addr->as_any.size = (uint8_t) socklen;
#endif

    return AH_ENONE;
}
