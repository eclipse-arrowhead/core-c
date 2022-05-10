// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_URING_TCP_H_
#define AH_INTERNAL_URING_TCP_H_

#define AH_I_TCP_CONN_PLATFORM_FIELDS \
 int _fd;                             \
 ah_buf_t _recv_buf;

#define AH_I_TCP_LISTENER_PLATFORM_FIELDS \
 int _fd;                                 \
 ah_sockaddr_t _raddr;                    \
 socklen_t _raddr_len;

#define AH_I_TCP_OBUFS_PLATFORM_FIELDS \
 struct iovec* _iov;                  \
 int _iovcnt;

#endif
