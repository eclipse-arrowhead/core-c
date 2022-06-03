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
# include <ws2ipdef.h>
#endif

ah_err_t ah_i_udp_sock_open(void* ctx, ah_udp_sock_t* sock, const ah_sockaddr_t* laddr)
{
    (void) ctx;

    if (sock == NULL || sock->_loop == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state != AH_I_UDP_SOCK_STATE_CLOSED) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_i_sock_open_bind(sock->_loop, laddr, SOCK_DGRAM, &sock->_fd);

    if (err == AH_ENONE) {
        sock->_is_ipv6 = (laddr != NULL ? laddr->as_any.family : AH_SOCKFAMILY_DEFAULT) == AH_SOCKFAMILY_IPV6;
        sock->_state = AH_I_UDP_SOCK_STATE_OPEN;
    }

    sock->_cbs->on_open(sock, err);

    return err;
}

ah_extern ah_err_t ah_udp_sock_get_laddr(const ah_udp_sock_t* sock, ah_sockaddr_t* laddr)
{
    if (sock == NULL || laddr == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state == AH_I_UDP_SOCK_STATE_CLOSED) {
        return AH_ESTATE;
    }
    return ah_i_sock_getsockname(sock->_fd, laddr);
}

ah_extern ah_err_t ah_udp_sock_set_multicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state == AH_I_UDP_SOCK_STATE_CLOSED) {
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

ah_extern ah_err_t ah_udp_sock_set_multicast_loopback(ah_udp_sock_t* sock, bool is_enabled)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state == AH_I_UDP_SOCK_STATE_CLOSED) {
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

    int value = is_enabled ? 1 : 0;
    if (setsockopt(sock->_fd, level, name, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }

    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_sock_set_reuseaddr(ah_udp_sock_t* sock, bool is_enabled)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state == AH_I_UDP_SOCK_STATE_CLOSED) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    if (setsockopt(sock->_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &value, sizeof(value)) != 0) {
        return errno;
    }
    return AH_ENONE;
}

ah_extern ah_err_t ah_udp_sock_set_unicast_hop_limit(ah_udp_sock_t* sock, uint8_t hop_limit)
{
    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state == AH_I_UDP_SOCK_STATE_CLOSED) {
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

ah_extern ah_err_t ah_udp_sock_join(ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state == AH_I_UDP_SOCK_STATE_CLOSED) {
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

ah_extern ah_err_t ah_udp_sock_leave(ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state == AH_I_UDP_SOCK_STATE_CLOSED) {
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
