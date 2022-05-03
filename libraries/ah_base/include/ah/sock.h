// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_SOCK_H_
#define AH_SOCK_H_

#include "internal/_sock.h"
#include "ip.h"

#include <stdbool.h>

#define AH_SOCKFAMILY_IPV4 AH_I_SOCKFAMILY_IPV4
#define AH_SOCKFAMILY_IPV6 AH_I_SOCKFAMILY_IPV6

#ifndef AH_SOCKFAMILY_DEFAULT
#    define AH_SOCKFAMILY_DEFAULT AH_SOCKFAMILY_IPV4
#elif (AH_SOCKFAMILY_DEFAULT != AH_SOCKFAMILY_IPV4) && (AH_SOCKFAMILY_DEFAULT != AH_SOCKFAMILY_IPV6)
#    error "AH_SOCKFAMILY_DEFAULT value is invalid; expected AH_SOCKFAMILY_IPV4 or AH_SOCKFAMILY_IPV6"
#endif

#if AH_I_SOCKADDR_HAS_SIZE
#    define AH_I_SOCKADDR_COMMON                                                                                       \
        uint8_t size;                                                                                                  \
        uint8_t family;
#else
#    define AH_I_SOCKADDR_COMMON uint16_t family;
#endif

struct ah_sockaddr_any {
    AH_I_SOCKADDR_COMMON
};

struct ah_sockaddr_ip {
    AH_I_SOCKADDR_COMMON
    uint16_t port;
};

struct ah_sockaddr_ipv4 {
    AH_I_SOCKADDR_COMMON
    uint16_t port;
    struct ah_ipaddr_v4 ipaddr;
};

struct ah_sockaddr_ipv6 {
    AH_I_SOCKADDR_COMMON
    uint16_t port;
    uint32_t flowinfo;
    struct ah_ipaddr_v6 ipaddr;
    uint32_t zone_id;
};

union ah_sockaddr {
    struct ah_sockaddr_any as_any;
    struct ah_sockaddr_ip as_ip;
    struct ah_sockaddr_ipv4 as_ipv4;
    struct ah_sockaddr_ipv6 as_ipv6;
};

static const ah_sockaddr_ipv4_t ah_sockaddr_ipv4_loopback = { AH_SOCKFAMILY_IPV4, 0u, { { 127u, 0u, 0u, 1u } } };
static const ah_sockaddr_ipv4_t ah_sockaddr_ipv4_wildcard = { AH_SOCKFAMILY_IPV4, 0u, { { 0u, 0u, 0u, 0u } } };
static const ah_sockaddr_ipv6_t ah_sockaddr_ipv6_loopback = { AH_SOCKFAMILY_IPV6, 0u, 0u,
    { { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u } }, 0u };
static const ah_sockaddr_ipv6_t ah_sockaddr_ipv6_wildcard = { AH_SOCKFAMILY_IPV6, 0u, 0u,
    { { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u } }, 0u };

ah_extern void ah_sockaddr_init_ipv4(ah_sockaddr_t* sockaddr, uint16_t port, const ah_ipaddr_v4_t* ipaddr);
ah_extern void ah_sockaddr_init_ipv6(ah_sockaddr_t* sockaddr, uint16_t port, const ah_ipaddr_v6_t* ipaddr);

ah_extern bool ah_sockaddr_is_ip(const ah_sockaddr_t* sockaddr);
ah_extern bool ah_sockaddr_is_ip_wildcard(const ah_sockaddr_t* sockaddr);
ah_extern bool ah_sockaddr_is_ip_with_port_zero(const ah_sockaddr_t* sockaddr);

#endif
