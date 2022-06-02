// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_UDP_H_
#define AH_INTERNAL_UDP_H_

#include "../defs.h"

#if AH_USE_IOCP
# include "_udp-iocp.h"
#elif AH_USE_KQUEUE
# include "_udp-kqueue.h"
#elif AH_USE_URING
# include "_udp-uring.h"
#endif

#define AH_I_UDP_SOCK_STATE_CLOSED    0u
#define AH_I_UDP_SOCK_STATE_OPEN      1u // Sends allowed.
#define AH_I_UDP_SOCK_STATE_RECEIVING 2u // Sends allowed.

#define AH_I_UDP_MSG_FIELDS \
 AH_I_UDP_MSG_PLATFORM_FIELDS

#define AH_I_UDP_SOCK_FIELDS           \
 ah_loop_t* _loop;                     \
 ah_udp_trans_t _trans;                \
 const ah_udp_sock_vtab_t* _vtab;      \
 struct ah_i_udp_msg_queue _msg_queue; \
 void* _user_data;                     \
 bool _is_ipv6;                        \
 uint8_t _state;                       \
 AH_I_UDP_SOCK_PLATFORM_FIELDS

struct ah_i_udp_msg_queue {
    ah_udp_msg_t* _head;
    ah_udp_msg_t* _end;
};

#endif
