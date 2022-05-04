// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_SOCK_H_
#define AH_INTERNAL_SOCK_H_

#include "../defs.h"

#if AH_HAS_BSD_SOCKETS
#    include "_sock-bsd.h"
#endif

#ifndef AH_I_SOCKADDR_HAS_SIZE
#    define AH_I_SOCKADDR_HAS_SIZE 0
#endif

#if AH_I_SOCKADDR_HAS_SIZE
#    define AH_I_SOCKADDR_PREAMBLE_IPV4 sizeof(ah_sockaddr_ipv4_t),
#    define AH_I_SOCKADDR_PREAMBLE_IPV6 sizeof(ah_sockaddr_ipv6_t),
#else
#    define AH_I_SOCKADDR_PREAMBLE_IPV4
#    define AH_I_SOCKADDR_PREAMBLE_IPV6
#endif

#endif
