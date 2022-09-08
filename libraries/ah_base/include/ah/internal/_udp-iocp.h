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
 SOCKET _fd;                          \
 uint32_t _ref_count;

#endif
