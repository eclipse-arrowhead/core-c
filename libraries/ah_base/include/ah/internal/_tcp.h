// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0.
//
// SPDX-License-Identifier: EPL-2.0

#ifndef AH_INTERNAL_TCP_H_
#define AH_INTERNAL_TCP_H_

#include "../defs.h"
#include "collections/slab.h"

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

#define AH_I_TCP_CONN_FIELDS        \
 ah_loop_t* _loop;                  \
 struct ah_i_slab* _owning_slab;    \
                                    \
 ah_tcp_trans_t _trans;             \
 const ah_tcp_conn_cbs_t* _cbs;     \
                                    \
 ah_tcp_in_t* _in;                  \
                                    \
 ah_tcp_shutdown_t _shutdown_flags; \
 uint8_t _state;                    \
                                    \
 AH_I_TCP_CONN_PLATFORM_FIELDS      \
                                    \
 void* _user_data;

#define AH_I_TCP_IN_FIELDS \
 ah_tcp_in_t** _owner_ptr;

#define AH_I_TCP_LISTENER_FIELDS     \
 ah_loop_t* _loop;                   \
 struct ah_i_slab _conn_slab;        \
                                     \
 ah_tcp_trans_t _trans;              \
 const ah_tcp_listener_cbs_t* _cbs;  \
 const ah_tcp_conn_cbs_t* _conn_cbs; \
                                     \
 uint8_t _state;                     \
                                     \
 AH_I_TCP_LISTENER_PLATFORM_FIELDS   \
                                     \
 void* _user_data;

#define AH_I_TCP_OUT_FIELDS \
 void* _owner;              \
                            \
 AH_I_TCP_OUT_PLATFORM_FIELDS

#endif
