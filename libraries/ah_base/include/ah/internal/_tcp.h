// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TCP_H_
#define AH_INTERNAL_TCP_H_

#include "../defs.h"

#if AH_USE_IOCP
# include "_tcp-iocp.h"
#elif AH_USE_KQUEUE
# include "_tcp-kqueue.h"
#elif AH_USE_URING
# include "_tcp-uring.h"
#endif

#define AH_I_TCP_CONN_STATE_CLOSED     0u
#define AH_I_TCP_CONN_STATE_OPEN       1u
#define AH_I_TCP_CONN_STATE_CONNECTING 2u
#define AH_I_TCP_CONN_STATE_CONNECTED  3u // Writes allowed.
#define AH_I_TCP_CONN_STATE_READING    4u // Writes allowed.

#define AH_I_TCP_LISTENER_STATE_CLOSED    0u
#define AH_I_TCP_LISTENER_STATE_OPEN      1u
#define AH_I_TCP_LISTENER_STATE_LISTENING 2u

#define AH_I_TCP_CONN_FIELDS           \
 ah_loop_t* _loop;                     \
 ah_tcp_trans_t _trans;                \
 const ah_tcp_conn_vtab_t* _vtab;      \
 void* _user_data;                     \
 ah_tcp_shutdown_t _shutdown_flags;    \
 uint8_t _state;                       \
 AH_I_TCP_CONN_PLATFORM_FIELDS

#define AH_I_TCP_LISTENER_FIELDS       \
 ah_loop_t* _loop;                     \
 ah_tcp_trans_t _trans;                \
 const ah_tcp_listener_vtab_t* _vtab;  \
 const ah_tcp_conn_vtab_t* _conn_vtab; \
 void* _user_data;                     \
 uint8_t _state;                       \
 AH_I_TCP_LISTENER_PLATFORM_FIELDS

#define AH_I_TCP_STREAM_FIELDS \
 AH_I_TCP_STREAM_PLATFORM_FIELDS

#endif
