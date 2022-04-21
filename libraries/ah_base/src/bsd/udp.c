// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/udp.h"

#include "ah/assert.h"
#include "ah/err.h"
#include "ah/loop.h"

#if AH_IS_WIN32
#    include <ws2ipdef.h>
#endif

ah_extern ah_err_t ah_udp_open(ah_udp_sock_t* sock, ah_loop_t* loop, const ah_sockaddr_t* local_addr, ah_udp_open_cb cb)
{
    if (sock == NULL || loop == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }

    ah_i_sockfd_t fd;
    ah_err_t err = ah_i_sock_open_bind(loop, SOCK_DGRAM, local_addr, &fd);

    if (err == AH_ENONE) {
        *sock = (ah_udp_sock_t) {
            ._loop = loop,
            ._fd = fd,
            ._is_ipv6 = local_addr->as_any.family == AH_SOCKFAMILY_IPV6,
            ._is_open = true,
        };
    }

    if (cb != NULL) {
        cb(sock, err);
        return AH_ENONE;
    }

    return err;
}

ah_extern ah_err_t ah_udp_get_local_addr(const ah_udp_sock_t* sock, ah_sockaddr_t* local_addr)
{
    if (sock == NULL || local_addr == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }
    return ah_i_sock_getsockname(sock->_fd, local_addr);
}

ah_extern ah_err_t ah_udp_set_multicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_MULTICAST_HOPS;
    }
    else {
        level = IPPROTO_IP;
        name = IP_MULTICAST_TTL;
    }

    int value = hop_limit;
    if (setsockopt(sock->_fd, level, name, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_set_multicast_loopback(ah_udp_sock_t* sock, bool loopback)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_MULTICAST_LOOP;
    }
    else {
        level = IPPROTO_IP;
        name = IP_MULTICAST_LOOP;
    }

    int value = loopback ? 1 : 0;
    if (setsockopt(sock->_fd, level, name, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_set_reuse_addr(ah_udp_sock_t* sock, bool reuse_addr)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }
    int value = reuse_addr ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_set_unicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_UNICAST_HOPS;
    }
    else {
        level = IPPROTO_IP;
        name = IP_TTL;
    }

    int value = hop_limit;
    if (setsockopt(sock->_fd, level, name, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_join(ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_JOIN_GROUP;
    }
    else {
        level = IPPROTO_IP;
        name = IP_ADD_MEMBERSHIP;
    }

    if (setsockopt(sock->_fd, level, name, (void*) group, sizeof(ah_udp_group_t)) != 0) {
        return errno;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_leave(ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (!sock->_is_open) {
        return AH_ESTATE;
    }

    int level;
    int name;

    if (sock->_is_ipv6) {
        level = IPPROTO_IPV6;
        name = IPV6_LEAVE_GROUP;
    }
    else {
        level = IPPROTO_IP;
        name = IP_DROP_MEMBERSHIP;
    }

    if (setsockopt(sock->_fd, level, name, (void*) group, sizeof(ah_udp_group_t)) != 0) {
        return errno;
    }

    return AH_ENONE;
}
