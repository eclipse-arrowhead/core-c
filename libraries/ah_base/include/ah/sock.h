// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_SOCK_H_
#define AH_SOCK_H_

#include "assert.h"
#include "defs.h"
#include "ip.h"

#include <stdbool.h>

#if AH_HAS_BSD_SOCKETS && AH_IS_WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#    include <winsock2.h>
#elif AH_USE_BSD_SOCKETS
#    include <netinet/in.h>
#endif

#if AH_USE_BSD_SOCKETS
#    ifdef SIN6_LEN
#        define AH_I_SOCKADDR_HAS_SIZE 1
#    endif

#    define AH_SOCKFAMILY_IPV4 AF_INET
#    define AH_SOCKFAMILY_IPV6 AF_INET6

#else
#    define AH_SOCKFAMILY_IPV4 1u
#    define AH_SOCKFAMILY_IPV6 2u
#endif

#ifndef AH_I_SOCKADDR_HAS_SIZE
#    define AH_I_SOCKADDR_HAS_SIZE 0
#endif

#if AH_I_SOCKADDR_HAS_SIZE
#    define AH_I_SOCKADDR_COMMON                                                                                       \
        uint8_t size;                                                                                                  \
        uint8_t family;
#else
#    define AH_I_SOCKADDR_COMMON uint16_t family;
#endif

#if AH_USE_BSD_SOCKETS && AH_IS_WIN32
typedef SOCKET ah_sockfd_t;
typedef int ah_socklen_t;
#elif AH_USE_BSD_SOCKETS
typedef int ah_sockfd_t;
typedef socklen_t ah_socklen_t;
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
#if AH_USE_BSD_SOCKETS
    uint32_t : 32; // flowinfo
#endif
    struct ah_ipaddr_v6 ipaddr;
    uint32_t zone_id;
};

union ah_sockaddr {
    struct ah_sockaddr_any as_any;
    struct ah_sockaddr_ip as_ip;
    struct ah_sockaddr_ipv4 as_ipv4;
    struct ah_sockaddr_ipv6 as_ipv6;
};

ah_extern void ah_sockaddr_init_ipv4(ah_sockaddr_t* sockaddr, uint16_t port, const ah_ipaddr_v4_t* ipaddr);
ah_extern void ah_sockaddr_init_ipv6(ah_sockaddr_t* sockaddr, uint16_t port, const ah_ipaddr_v6_t* ipaddr);

ah_extern bool ah_sockaddr_is_ip(const ah_sockaddr_t* sockaddr);
ah_extern bool ah_sockaddr_is_ip_wildcard(const ah_sockaddr_t* sockaddr);
ah_extern bool ah_sockaddr_is_ip_with_port_zero(const ah_sockaddr_t* sockaddr);

#if AH_USE_BSD_SOCKETS
ah_extern ah_socklen_t ah_sockaddr_get_size(const ah_sockaddr_t* sockaddr);
ah_extern struct sockaddr* ah_sockaddr_cast(ah_sockaddr_t* sockaddr);
ah_extern const struct sockaddr* ah_sockaddr_cast_const(const ah_sockaddr_t* sockaddr);
#endif

#endif
