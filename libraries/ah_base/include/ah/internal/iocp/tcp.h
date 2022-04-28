// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_IOCP_TCP_H_
#define AH_INTERNAL_IOCP_TCP_H_

#include <winsock2.h>
#include <mswsock.h>

#define AH_I_TCP_LISTEN_CTX_PLATFORM_FIELDS                                                                            \
    char _accept_buffer[sizeof(struct sockaddr_storage) * 2u + 32u];                                                   \
    ah_i_sockfd_t _accept_fd;

#define AH_I_TCP_READ_CTX_PLATFORM_FIELDS                                                                              \
    ah_bufs_t _bufs;                                                                                               \
    DWORD _recv_flags;

#define AH_I_TCP_SOCK_PLATFORM_FIELDS                                                                                  \
    int _sockfamily;                                                                                                   \
    bool _is_listening;                                                                                                \
    ah_i_sockfd_t _fd;                                                                                                 \
    LPFN_ACCEPTEX _AcceptEx;                                                                                           \
    LPFN_CONNECTEX _ConnectEx;                                                                                         \
    LPFN_GETACCEPTEXSOCKADDRS _GetAcceptExSockaddrs;

#define AH_I_TCP_WRITE_CTX_PLATFORM_FIELDS

#endif
