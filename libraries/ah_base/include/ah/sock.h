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

#if AH_USE_BSD_SOCKETS
#    if AH_USE_IOCP
#        include <winsock2.h>
#    else
#        include <netinet/in.h>
#    endif

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

#if AH_USE_BSD_SOCKETS && AH_USE_IOCP
typedef SOCKET ah_sockfd_t;
#elif AH_USE_BSD_SOCKETS
typedef int ah_sockfd_t;
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

ah_extern bool ah_sockaddr_is_ip(const union ah_sockaddr* sockaddr);
ah_extern bool ah_sockaddr_is_ip_wildcard(const union ah_sockaddr* sockaddr);
ah_extern bool ah_sockaddr_is_ip_with_port_zero(const union ah_sockaddr* sockaddr);

#if AH_USE_BSD_SOCKETS
ah_extern socklen_t ah_sockaddr_get_size(const union ah_sockaddr* sockaddr);
ah_extern struct sockaddr* ah_sockaddr_cast(union ah_sockaddr* sockaddr);
ah_extern const struct sockaddr* ah_sockaddr_cast_const(const union ah_sockaddr* sockaddr);
#endif

#endif
