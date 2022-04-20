// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_IOCP_UDP_H_
#define AH_INTERNAL_IOCP_UDP_H_

#define AH_I_UDP_RECV_CTX_PLATFORM_FIELDS                                                                              \
    union ah_sockaddr _remote_addr;                                                                                    \
    WSAMSG _wsa_msg;

#define AH_I_UDP_SEND_CTX_PLATFORM_FIELDS WSAMSG _wsa_msg;
#define AH_I_UDP_SOCK_PLATFORM_FIELDS     ah_i_sockfd_t _fd;

#endif
