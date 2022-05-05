// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_IOCP_TCP_H_
#define AH_INTERNAL_IOCP_TCP_H_

#include <winsock2.h>

#include <mswsock.h>
#include <ws2ipdef.h>

#define AH_I_TCP_LISTENER_ACCEPT_BUFFER_ADDR_SIZE (sizeof(struct sockaddr_in6) + 16u)
#define AH_I_TCP_LISTENER_ACCEPT_BUFFER_SIZE      (AH_I_TCP_LISTENER_ACCEPT_BUFFER_ADDR_SIZE * 2u)

#define AH_I_TCP_CONN_PLATFORM_FIELDS                                                                                  \
    DWORD _recv_flags;                                                                                                 \
    SOCKET _fd;                                                                                                        \
    ah_buf_t _recv_buf;                                                                                                \
    LPFN_CONNECTEX _ConnectEx;

#define AH_I_TCP_LISTENER_PLATFORM_FIELDS                                                                              \
    bool _is_listening;                                                                                                \
    int _sockfamily;                                                                                                   \
    SOCKET _fd;                                                                                                        \
    SOCKET _accept_fd;                                                                                                 \
    char _accept_buffer[AH_I_TCP_LISTENER_ACCEPT_BUFFER_SIZE];                                                         \
    LPFN_ACCEPTEX _AcceptEx;                                                                                           \
    LPFN_GETACCEPTEXSOCKADDRS _GetAcceptExSockaddrs;

#define AH_I_TCP_OMSG_PLATFORM_FIELDS                                                                                  \
    WSABUF* _buffers;                                                                                                  \
    ULONG _buffer_count;

#endif
