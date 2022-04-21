// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_POSIX_SOCK_H_
#define AH_INTERNAL_POSIX_SOCK_H_

#include "ah/defs.h"

#if AH_HAS_POSIX
#    include <netinet/in.h>
#elif AH_IS_WIN32
#    define WIN32_LEAN_AND_MEAN
#    include <windows.h>
#    include <winsock2.h>
#endif

#ifdef SIN6_LEN
#    define AH_I_SOCKADDR_HAS_SIZE 1
#endif

#define AH_I_SOCKFAMILY_IPV4 AF_INET
#define AH_I_SOCKFAMILY_IPV6 AF_INET6

#if AH_HAS_POSIX
typedef int ah_i_sockfd_t;
typedef socklen_t ah_i_socklen_t;
#elif AH_IS_WIN32
typedef SOCKET ah_i_sockfd_t;
typedef int ah_i_socklen_t;
#endif

ah_extern ah_i_socklen_t ah_i_sockaddr_get_size(const ah_sockaddr_t* sockaddr);

ah_extern_inline ah_sockaddr_t* ah_i_sockaddr_from_bsd(struct sockaddr* sockaddr)
{
    return (ah_sockaddr_t*) sockaddr;
}

ah_extern_inline const ah_sockaddr_t* ah_i_sockaddr_const_from_bsd(const struct sockaddr* sockaddr)
{
    return (const ah_sockaddr_t*) sockaddr;
}

ah_extern_inline struct sockaddr* ah_i_sockaddr_into_bsd(ah_sockaddr_t* sockaddr)
{
    return (struct sockaddr*) sockaddr;
}

ah_extern_inline const struct sockaddr* ah_i_sockaddr_const_into_bsd(const ah_sockaddr_t* sockaddr)
{
    return (const struct sockaddr*) sockaddr;
}

ah_extern ah_err_t ah_i_sock_open(ah_loop_t* loop, int sockfamily, int type, ah_i_sockfd_t* fd);
ah_extern ah_err_t ah_i_sock_open_bind(ah_loop_t* loop, int type, const ah_sockaddr_t* local_addr, ah_i_sockfd_t* fd);
ah_extern ah_err_t ah_i_sock_close(ah_loop_t* loop, ah_i_sockfd_t fd);

ah_extern ah_err_t ah_i_sock_getsockname(ah_i_sockfd_t fd, ah_sockaddr_t* local_addr);
ah_extern ah_err_t ah_i_sock_getpeername(ah_i_sockfd_t fd, ah_sockaddr_t* remote_addr);

#endif
