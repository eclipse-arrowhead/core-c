// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_IOCP_UDP_H_
#define AH_INTERNAL_IOCP_UDP_H_

#include <mswsock.h>
#include <winsock2.h>

#define AH_I_UDP_SOCK_PLATFORM_FIELDS                                                                                  \
    SOCKET _fd;                                                                                                        \
    ah_sockaddr_t _raddr;                                                                                        \
    struct msghdr _recv_wsamsg;                                                                                        \
    struct msghdr _send_wsamsg;                                                                                        \
    LPFN_WSARECVMSG _WSARecvMsg;

#endif
