// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_IOCP_UDP_H_
#define AH_INTERNAL_IOCP_UDP_H_

#include <winsock2.h>

#include <mswsock.h>

#define AH_I_UDP_IN_PLATFORM_FIELDS \
 DWORD _recv_flags;                 \
 ah_sockaddr_t _recv_from;          \
 INT _recv_from_len;

#define AH_I_UDP_OUT_PLATFORM_FIELDS \
 WSAMSG _wsamsg;                     \
 ah_udp_sock_t* _sock;

#define AH_I_UDP_SOCK_PLATFORM_FIELDS \
 SOCKET _fd;

#endif
