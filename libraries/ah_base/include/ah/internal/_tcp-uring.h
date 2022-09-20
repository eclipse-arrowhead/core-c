// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TCP_URING_H_
#define AH_INTERNAL_TCP_URING_H_

#include "../sock.h"

#define AH_I_TCP_CONN_PLATFORM_FIELDS \
 int _fd;                             \
 uint32_t _ref_count;                 \
 struct ah_i_loop_evt* _read_evt;

#define AH_I_TCP_LISTENER_PLATFORM_FIELDS \
 int _fd;                                 \
 uint32_t _ref_count;                     \
 ah_sockaddr_t _raddr;                    \
 socklen_t _raddr_len;

#define AH_I_TCP_OUT_PLATFORM_FIELDS \
 ah_tcp_conn_t* _conn;

#endif
