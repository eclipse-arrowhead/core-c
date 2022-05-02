// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_IOCP_TCP_H_
#define AH_INTERNAL_IOCP_TCP_H_

#include <mswsock.h>
#include <winsock2.h>

#define AH_I_TCP_CONN_PLATFORM_FIELDS                                                                                  \
    DWORD _recv_flags;                                                                                                 \
    SOCKET _fd;                                                                                                        \
    ah_bufs_t _read_bufs;                                                                                              \
    ah_bufs_t _write_bufs;                                                                                             \
    LPFN_CONNECTEX _ConnectEx;

#define AH_I_TCP_LISTENER_PLATFORM_FIELDS                                                                              \
    bool _is_listening;                                                                                                \
    int _sockfamily;                                                                                                   \
    SOCKET _fd;                                                                                                        \
    SOCKET _accept_fd;                                                                                                 \
    char _accept_buffer[sizeof(struct sockaddr_storage) * 2u + 32u];                                                   \
    LPFN_ACCEPTEX _AcceptEx;                                                                                           \
    LPFN_GETACCEPTEXSOCKADDRS _GetAcceptExSockaddrs;

#endif
