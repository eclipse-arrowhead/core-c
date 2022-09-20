// SPDX-License-Identifier: EPL-2.0

#include "ah/sock.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#if AH_IS_DARWIN
# include <fcntl.h>
#elif AH_IS_WIN32
# include <ws2ipdef.h>
#endif

#if AH_HAS_POSIX
# include <unistd.h>
#endif

#if AH_IS_WIN32
# define close closesocket
#endif

ah_i_socklen_t ah_i_sockaddr_get_size(const ah_sockaddr_t* sockaddr)
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

ah_err_t ah_i_sock_open(ah_loop_t* loop, const int sockfamily, const int type, ah_i_sockfd_t* fd)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(fd != NULL);

    if (ah_loop_is_term(loop)) {
        return AH_ECANCELED;
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

#if AH_USE_IOCP

    ah_err_t err;

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

#elif AH_IS_DARWIN

    ah_err_t err;

    if (fcntl(fd0, F_SETFL, O_NONBLOCK, 0) == -1) {
        err = errno;
        goto close_fd0_and_return;
    }

#endif

    *fd = fd0;

    return AH_ENONE;

#if AH_USE_IOCP || AH_IS_DARWIN

close_fd0_and_return:
    (void) close(fd0);

    return err;

#endif
}

ah_err_t ah_i_sock_open_bind(ah_loop_t* loop, const ah_sockaddr_t* laddr, int type, ah_i_sockfd_t* fd)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(laddr != NULL);
    ah_assert_if_debug(fd != NULL);

    ah_i_sockfd_t fd0;
    ah_err_t err = ah_i_sock_open(loop, laddr->as_any.family, type, &fd0);
    if (err != AH_ENONE) {
        return err;
    }

#if AH_IS_WIN32
    ah_sockaddr_t laddr_copy = *laddr;
    laddr_copy.as_ip.port = htons(laddr->as_ip.port);
    if (bind(fd0, ah_i_sockaddr_const_into_bsd(&laddr_copy), ah_i_sockaddr_get_size(laddr)) != 0) {
        err = WSAGetLastError();
        goto close_fd0_and_return;
    }
#else
    if (laddr->as_ip.port != 0u || !ah_sockaddr_is_ip_wildcard(laddr)) {
        ah_sockaddr_t laddr_copy = *laddr;
        laddr_copy.as_ip.port = htons(laddr->as_ip.port);
        if (bind(fd0, ah_i_sockaddr_const_into_bsd(&laddr_copy), ah_i_sockaddr_get_size(laddr)) != 0) {
            err = errno;
            goto close_fd0_and_return;
        }
    }
#endif

    *fd = fd0;

    return AH_ENONE;

close_fd0_and_return:
    (void) close(fd0);

    return err;
}

ah_err_t ah_i_sock_close(ah_i_sockfd_t fd)
{
    if (close(fd) != 0) {
#if AH_IS_WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
    }

    return AH_ENONE;
}

ah_err_t ah_i_sock_getsockname(ah_i_sockfd_t fd, ah_sockaddr_t* laddr)
{
    ah_assert_if_debug(laddr != NULL);

    ah_i_socklen_t socklen = sizeof(ah_sockaddr_t);
    if (getsockname(fd, ah_i_sockaddr_into_bsd(laddr), &socklen) != 0) {
#if AH_IS_WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
    }

#if AH_I_SOCKADDR_HAS_SIZE
    ah_assert_if_debug(socklen <= UINT8_MAX);
    laddr->as_any.size = (uint8_t) socklen;
#endif

#if AH_IS_WIN32
    if (ah_sockaddr_is_ip_wildcard(laddr)) {
        if (laddr->as_ip.family == AH_SOCKFAMILY_IPV4) {
            memcpy(&laddr->as_ipv4.ipaddr, &ah_sockaddr_ipv4_loopback.ipaddr, sizeof(ah_sockaddr_ipv4_loopback.ipaddr));
        }
        else {
            memcpy(&laddr->as_ipv6.ipaddr, &ah_sockaddr_ipv6_loopback.ipaddr, sizeof(ah_sockaddr_ipv6_loopback.ipaddr));
        }
    }
#endif

    return AH_ENONE;
}

ah_err_t ah_i_sock_getpeername(ah_i_sockfd_t fd, ah_sockaddr_t* raddr)
{
    ah_assert_if_debug(raddr != NULL);

    ah_i_socklen_t socklen = sizeof(ah_sockaddr_t);
    if (getpeername(fd, ah_i_sockaddr_into_bsd(raddr), &socklen) != 0) {
#if AH_IS_WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
    }

#if AH_I_SOCKADDR_HAS_SIZE
    ah_assert_if_debug(socklen <= UINT8_MAX);
    raddr->as_any.size = (uint8_t) socklen;
#endif

    return AH_ENONE;
}

ah_err_t ah_i_sock_setsockopt(ah_i_sockfd_t fd, int level, int name, const void* value, ah_i_socklen_t size)
{
    if (setsockopt(fd, level, name, value, size) != 0) {
#if AH_IS_WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
    }

    return AH_ENONE;
}

ah_err_t ah_i_sock_shutdown(ah_i_sockfd_t fd, int how)
{
    if (shutdown(fd, how) != 0) {
#if AH_IS_WIN32
        return WSAGetLastError();
#else
        return errno;
#endif
    }

    return AH_ENONE;
}
