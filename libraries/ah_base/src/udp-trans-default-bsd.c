// SPDX-License-Identifier: EPL-2.0

#include "ah/err.h"
#include "ah/udp.h"

#if AH_IS_WIN32
# include <ws2ipdef.h>
#endif

ah_err_t ah_i_udp_trans_default_sock_open(void* ctx, ah_udp_sock_t* sock, const ah_sockaddr_t* laddr)
{
    (void) ctx;

    if (sock == NULL || laddr == NULL) {
        return AH_EINVAL;
    }
    if (!ah_sockaddr_is_ip(laddr)) {
        return AH_EAFNOSUPPORT;
    }
    if (sock->_state != AH_I_UDP_SOCK_STATE_INITIALIZED) {
        return AH_ESTATE;
    }

    ah_err_t err = ah_i_sock_open_bind(sock->_loop, laddr, SOCK_DGRAM, &sock->_fd);

    if (err == AH_ENONE) {
        sock->_sock_family = laddr->as_any.family;
        sock->_state = AH_I_UDP_SOCK_STATE_OPEN;
    }

    sock->_obs.cbs->on_open(sock->_obs.ctx, sock, err);

    return err;
}

ah_err_t ah_i_udp_trans_default_sock_get_laddr(void* ctx, const ah_udp_sock_t* sock, ah_sockaddr_t* laddr)
{
    (void) ctx;

    if (sock == NULL || laddr == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state <= AH_I_UDP_SOCK_STATE_CLOSED) {
        return AH_ESTATE;
    }
    return ah_i_sock_getsockname(sock->_fd, laddr);
}

ah_err_t ah_i_udp_trans_default_sock_set_multicast_hop_limit(void* ctx, ah_udp_sock_t* sock, uint8_t hop_limit)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state <= AH_I_UDP_SOCK_STATE_CLOSING) {
        return AH_ESTATE;
    }

    int level;
    int name;

    switch (sock->_sock_family) {
    case AH_SOCKFAMILY_IPV6:
        level = IPPROTO_IPV6;
        name = IPV6_MULTICAST_HOPS;
        break;

    case AH_SOCKFAMILY_IPV4:
        level = IPPROTO_IP;
        name = IP_MULTICAST_TTL;
        break;

    default:
        return AH_EAFNOSUPPORT;
    }

    int value = hop_limit;
    return ah_i_sock_setsockopt(sock->_fd, level, name, &value, sizeof(value));
}

ah_err_t ah_i_udp_trans_default_sock_set_multicast_loopback(void* ctx, ah_udp_sock_t* sock, bool is_enabled)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state <= AH_I_UDP_SOCK_STATE_CLOSING) {
        return AH_ESTATE;
    }

    int level;
    int name;

    switch (sock->_sock_family) {
    case AH_SOCKFAMILY_IPV6:
        level = IPPROTO_IPV6;
        name = IPV6_MULTICAST_LOOP;
        break;

    case AH_SOCKFAMILY_IPV4:
        level = IPPROTO_IP;
        name = IP_MULTICAST_LOOP;
        break;

    default:
        return AH_EAFNOSUPPORT;
    }

    int value = is_enabled ? 1 : 0;
    return ah_i_sock_setsockopt(sock->_fd, level, name, &value, sizeof(value));
}

ah_err_t ah_i_udp_trans_default_sock_set_reuseaddr(void* ctx, ah_udp_sock_t* sock, bool is_enabled)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state <= AH_I_UDP_SOCK_STATE_CLOSING) {
        return AH_ESTATE;
    }
    int value = is_enabled ? 1 : 0;
    return ah_i_sock_setsockopt(sock->_fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value));
}

ah_err_t ah_i_udp_trans_default_sock_set_unicast_hop_limit(void* ctx, ah_udp_sock_t* sock, uint8_t hop_limit)
{
    (void) ctx;

    if (sock == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state <= AH_I_UDP_SOCK_STATE_CLOSING) {
        return AH_ESTATE;
    }

    int level;
    int name;

    switch (sock->_sock_family) {
    case AH_SOCKFAMILY_IPV6:
        level = IPPROTO_IPV6;
        name = IPV6_UNICAST_HOPS;
        break;

    case AH_SOCKFAMILY_IPV4:
        level = IPPROTO_IP;
        name = IP_TTL;
        break;

    default:
        return AH_EAFNOSUPPORT;
    }

    int value = hop_limit;
    return ah_i_sock_setsockopt(sock->_fd, level, name, &value, sizeof(value));
}

ah_err_t ah_i_udp_trans_default_sock_join(void* ctx, ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    (void) ctx;

    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state <= AH_I_UDP_SOCK_STATE_CLOSING) {
        return AH_ESTATE;
    }

    int level;
    int name;
    ah_i_socklen_t size;

    switch (sock->_sock_family) {
    case AH_SOCKFAMILY_IPV6:
        level = IPPROTO_IPV6;
        name = IPV6_JOIN_GROUP;
        size = sizeof(ah_udp_group_ipv6_t);
        break;

    case AH_SOCKFAMILY_IPV4:
        level = IPPROTO_IP;
        name = IP_ADD_MEMBERSHIP;
        size = sizeof(ah_udp_group_ipv4_t);
        break;

    default:
        return AH_EAFNOSUPPORT;
    }

    return ah_i_sock_setsockopt(sock->_fd, level, name, (void*) group, size);
}

ah_err_t ah_i_udp_trans_default_sock_leave(void* ctx, ah_udp_sock_t* sock, const ah_udp_group_t* group)
{
    (void) ctx;

    if (sock == NULL || group == NULL) {
        return AH_EINVAL;
    }
    if (sock->_state <= AH_I_UDP_SOCK_STATE_CLOSING) {
        return AH_ESTATE;
    }

    int level;
    int name;
    ah_i_socklen_t size;

    switch (sock->_sock_family) {
    case AH_SOCKFAMILY_IPV6:
        level = IPPROTO_IPV6;
        name = IPV6_LEAVE_GROUP;
        size = sizeof(ah_udp_group_ipv6_t);
        break;

    case AH_SOCKFAMILY_IPV4:
        level = IPPROTO_IP;
        name = IP_DROP_MEMBERSHIP;
        size = sizeof(ah_udp_group_ipv4_t);
        break;

    default:
        return AH_EAFNOSUPPORT;
    }

    return ah_i_sock_setsockopt(sock->_fd, level, name, (void*) group, size);
}
