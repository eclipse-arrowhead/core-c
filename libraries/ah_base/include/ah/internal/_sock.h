// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_SOCK_H_
#define AH_INTERNAL_SOCK_H_

#include "../defs.h"

#if AH_HAS_BSD_SOCKETS
# include "_sock-bsd.h"
#endif

#ifndef AH_I_SOCKADDR_HAS_SIZE
# define AH_I_SOCKADDR_HAS_SIZE 0
#endif

#if AH_I_SOCKADDR_HAS_SIZE
# define AH_I_SOCKADDR_PREAMBLE_IPV4 sizeof(ah_sockaddr_ipv4_t),
# define AH_I_SOCKADDR_PREAMBLE_IPV6 sizeof(ah_sockaddr_ipv6_t),
#else
# define AH_I_SOCKADDR_PREAMBLE_IPV4
# define AH_I_SOCKADDR_PREAMBLE_IPV6
#endif

#if AH_I_SOCKADDR_HAS_SIZE
# define AH_I_SOCKADDR_COMMON \
  uint8_t size;               \
  uint8_t family;
#else
# define AH_I_SOCKADDR_COMMON \
  uint16_t family;
#endif

#endif
