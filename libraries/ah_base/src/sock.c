// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/sock.h"

#include "ah/loop-internal.h"
#include "ah/loop.h"
#include "sock-internal.h"

#if AH_USE_BSD_SOCKETS
#    include <fcntl.h>
#    include <unistd.h>
#endif

ah_extern void ah_sockaddr_init_ipv4(union ah_sockaddr* sockaddr, uint16_t port, const struct ah_ipaddr_v4* ipaddr)
{
    ah_assert_if_debug(sockaddr != NULL);
    ah_assert_if_debug(ipaddr != NULL);

    sockaddr->as_ipv4 = (struct ah_sockaddr_ipv4)
    {
#if AH_I_SOCKADDR_HAS_SIZE
        .size = sizeof(struct sockaddr_in),
#endif
        .family = AH_SOCKFAMILY_IPV4, .port = port, .ipaddr = *ipaddr,
    };
}

ah_extern void ah_sockaddr_init_ipv6(union ah_sockaddr* sockaddr, uint16_t port, const struct ah_ipaddr_v6* ipaddr)
{
    ah_assert_if_debug(sockaddr != NULL);
    ah_assert_if_debug(ipaddr != NULL);

    sockaddr->as_ipv6 = (struct ah_sockaddr_ipv6)
    {
#if AH_I_SOCKADDR_HAS_SIZE
        .size = sizeof(struct sockaddr_in6),
#endif
        .family = AH_SOCKFAMILY_IPV4, .port = port, .ipaddr = *ipaddr,
    };
}

ah_extern bool ah_sockaddr_is_ip(const union ah_sockaddr* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);
    return sockaddr->as_any.family == AH_SOCKFAMILY_IPV4 || sockaddr->as_any.family == AH_SOCKFAMILY_IPV6;
}

ah_extern bool ah_sockaddr_is_ip_wildcard(const union ah_sockaddr* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);

    switch (sockaddr->as_any.family) {
    case AH_SOCKFAMILY_IPV4:
        return ah_ipaddr_v4_is_wildcard(sockaddr->as_ipv4.ipaddr);

    case AH_SOCKFAMILY_IPV6:
        return ah_ipaddr_v6_is_wildcard(sockaddr->as_ipv6.ipaddr);

    default:
        return false;
    }
}

ah_extern bool ah_sockaddr_is_ip_with_port_zero(const union ah_sockaddr* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);

    switch (sockaddr->as_any.family) {
    case AH_SOCKFAMILY_IPV4:
    case AH_SOCKFAMILY_IPV6:
        return sockaddr->as_ip.port == 0u;

    default:
        return false;
    }
}

#if AH_USE_BSD_SOCKETS

ah_extern socklen_t ah_sockaddr_get_size(const union ah_sockaddr* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);

#    if AH_I_SOCKADDR_HAS_SIZE
    if (sockaddr->as_any.size != 0u) {
        return sockaddr->as_any.size;
    }
#    endif

    switch (sockaddr->as_any.family) {
    case AH_SOCKFAMILY_IPV4:
        return sizeof(struct sockaddr_in);

    case AH_SOCKFAMILY_IPV6:
        return sizeof(struct sockaddr_in6);

    default:
        ah_abort();
    }
}

ah_extern struct sockaddr* ah_sockaddr_cast(union ah_sockaddr* sockaddr)
{
    return (struct sockaddr*) sockaddr;
}

ah_extern const struct sockaddr* ah_sockaddr_cast_const(const union ah_sockaddr* sockaddr)
{
    return (const struct sockaddr*) sockaddr;
}

ah_extern ah_err_t ah_i_sock_open(struct ah_loop* loop, int type, const union ah_sockaddr* local_addr,
    ah_i_sockfd_t* fd)
{
    ah_assert_if_debug(loop != NULL);
    ah_assert_if_debug(local_addr != NULL);
    ah_assert_if_debug(fd != NULL);

    if (ah_loop_is_term(loop)) {
        return AH_ESTATE;
    }

    ah_err_t err = AH_ENONE;

    int domain;
    if (local_addr->as_any.family == AH_SOCKFAMILY_IPV4) {
        domain = PF_INET;
    }
    else if (local_addr->as_any.family == AH_SOCKFAMILY_IPV6) {
        domain = PF_INET6;
    }
    else {
        return AH_EINVAL;
    }

    int fd0 = socket(domain, type, 0);
    if (fd0 == -1) {
        return errno;
    }

    if (fcntl(fd0, F_SETFL, O_NONBLOCK, 0) == -1) {
        err = errno;
        goto close_fd_and_return;
    }

    if (local_addr->as_ip.port != 0u || !ah_sockaddr_is_ip_wildcard(local_addr)) {
        if (bind(fd0, ah_sockaddr_cast_const(local_addr), ah_sockaddr_get_size(local_addr)) != 0) {
            err = errno;
            goto close_fd_and_return;
        }
    }

    *fd = fd0;

    return err;

close_fd_and_return:
    close(fd0);
    return err;
}

ah_extern ah_err_t ah_i_sock_close(struct ah_loop* loop, ah_i_sockfd_t fd)
{
    ah_assert_if_debug(loop != NULL);

    if (close(fd) != 0) {
        if (!(errno == AH_EINTR && ah_i_loop_try_set_pending_err(loop, AH_EINTR))) {
            return errno;
        }
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_sock_getsockname(ah_i_sockfd_t fd, union ah_sockaddr* local_addr)
{
    ah_assert_if_debug(local_addr != NULL);

    socklen_t socklen = sizeof(union ah_sockaddr);
    if (getsockname(fd, ah_sockaddr_cast(local_addr), &socklen) != 0) {
        return errno;
    }

#    if AH_I_SOCKADDR_HAS_SIZE
    ah_assert_if_debug(socklen <= UINT8_MAX);
    local_addr->as_any.size = (uint8_t) socklen;
#    endif

    return AH_ENONE;
}

ah_extern ah_err_t ah_i_sock_getpeername(ah_i_sockfd_t fd, union ah_sockaddr* remote_addr)
{
    ah_assert_if_debug(remote_addr != NULL);

    socklen_t socklen = sizeof(union ah_sockaddr);
    if (getpeername(fd, ah_sockaddr_cast(remote_addr), &socklen) != 0) {
        return errno;
    }

#    if AH_I_SOCKADDR_HAS_SIZE
    ah_assert_if_debug(socklen <= UINT8_MAX);
    remote_addr->as_any.size = (uint8_t) socklen;
#    endif

    return AH_ENONE;
}

#endif
