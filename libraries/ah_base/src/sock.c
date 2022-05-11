// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#include "ah/sock.h"

#include "ah/assert.h"

ah_extern void ah_sockaddr_init_ipv4(ah_sockaddr_t* sockaddr, uint16_t port, const struct ah_ipaddr_v4* ipaddr)
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

ah_extern void ah_sockaddr_init_ipv6(ah_sockaddr_t* sockaddr, uint16_t port, const struct ah_ipaddr_v6* ipaddr)
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

ah_extern bool ah_sockaddr_is_ip(const ah_sockaddr_t* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);
    return sockaddr->as_any.family == AH_SOCKFAMILY_IPV4 || sockaddr->as_any.family == AH_SOCKFAMILY_IPV6;
}

ah_extern bool ah_sockaddr_is_ip_wildcard(const ah_sockaddr_t* sockaddr)
{
    ah_assert_if_debug(sockaddr != NULL);

    switch (sockaddr->as_any.family) {
    case AH_SOCKFAMILY_IPV4:
        return ah_ipaddr_v4_is_wildcard(&sockaddr->as_ipv4.ipaddr);

    case AH_SOCKFAMILY_IPV6:
        return ah_ipaddr_v6_is_wildcard(&sockaddr->as_ipv6.ipaddr);

    default:
        return false;
    }
}

ah_extern bool ah_sockaddr_is_ip_with_port_zero(const ah_sockaddr_t* sockaddr)
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
