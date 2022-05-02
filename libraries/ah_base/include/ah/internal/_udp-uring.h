// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_URING_UDP_H_
#define AH_INTERNAL_URING_UDP_H_

#define AH_I_UDP_OMSG_PLATFORM_FIELDS struct msghdr _msghdr;

#define AH_I_UDP_SOCK_PLATFORM_FIELDS                                                                                  \
    int _fd;                                                                                                           \
    ah_sockaddr_t _recv_addr;                                                                                          \
    struct msghdr _recv_msghdr;

#endif
