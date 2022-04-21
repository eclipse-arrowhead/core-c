// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_KQUEUE_TCP_H_
#define AH_INTERNAL_KQUEUE_TCP_H_

#define AH_I_TCP_LISTEN_CTX_PLATFORM_FIELDS
#define AH_I_TCP_READ_CTX_PLATFORM_FIELDS

#define AH_I_TCP_SOCK_PLATFORM_FIELDS                                                                                           \
    struct ah_i_loop_evt* _read_or_listen_evt;                                                                         \
    ah_i_sockfd_t _fd;

#define AH_I_TCP_WRITE_CTX_PLATFORM_FIELDS

#endif
