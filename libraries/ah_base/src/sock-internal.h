// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef SRC_SOCK_INTERNAL_H_
#define SRC_SOCK_INTERNAL_H_

#include "ah/defs.h"
#include "ah/err.h"

#include <stdint.h>

#if AH_USE_BSD_SOCKETS
#    if AH_IS_WIN32
#        if !defined(_WINSOCKAPI_)
#            define _WINSOCKAPI_
#            include <Windows.h>
#            include <Winsock2.h>
#        endif
#    else
#        include <netinet/in.h>
#    endif
#    define AH_I_SOCK_STREAM SOCK_STREAM
#    define AH_I_SOCK_DGRAM  SOCK_DGRAM
#endif

#if AH_USE_BSD_SOCKETS && AH_IS_WIN32
typedef SOCKET ah_i_sockfd_t;
#elif AH_USE_BSD_SOCKETS
typedef int ah_i_sockfd_t;
#endif

#if AH_USE_BSD_SOCKETS
ah_extern ah_err_t ah_i_sock_open(ah_loop_t* loop, int type, const ah_sockaddr_t* local_addr, ah_i_sockfd_t* fd);
ah_extern ah_err_t ah_i_sock_close(ah_loop_t* loop, ah_i_sockfd_t fd);

ah_extern ah_err_t ah_i_sock_getsockname(ah_i_sockfd_t fd, ah_sockaddr_t* local_addr);
ah_extern ah_err_t ah_i_sock_getpeername(ah_i_sockfd_t fd, ah_sockaddr_t* remote_addr);
#endif

#endif
