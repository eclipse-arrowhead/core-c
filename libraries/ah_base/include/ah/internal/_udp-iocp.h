// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_IOCP_UDP_H_
#define AH_INTERNAL_IOCP_UDP_H_

#include <winsock2.h>

#include <mswsock.h>

#define AH_I_UDP_OMSG_PLATFORM_FIELDS WSAMSG _wsamsg;
#define AH_I_UDP_SOCK_PLATFORM_FIELDS                                                                                  \
    int _recv_addr_len;                                                                                                \
    DWORD _recv_flags;                                                                                                 \
    SOCKET _fd;                                                                                                        \
    ah_sockaddr_t _recv_addr;                                                                                          \
    ah_buf_t _recv_buf;

#endif
